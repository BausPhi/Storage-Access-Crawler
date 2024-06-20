import hashlib
import os
import traceback
from datetime import datetime
from logging import Logger
from typing import List, Optional

from playwright.sync_api import Response, Frame
from peewee import ForeignKeyField, TextField, BooleanField, DateTimeField

from database import URL, database, BaseModel, Task
from modules.module import Module


####### Database Models ###############################################################################################


class Document(BaseModel):
    sha1 = TextField(unique=True)
    url = TextField()
    saa = BooleanField(default=False)


class Script(BaseModel):
    sha1 = TextField(unique=True)
    url = TextField()
    saa = BooleanField(default=False)


class DocumentInclusion(BaseModel):
    document = ForeignKeyField(Document, backref="document_inclusions")
    top_level_site = ForeignKeyField(Document)
    parent = ForeignKeyField("self", null=True, backref="children") # Top-level if parent is 'null'
    crawl_date = DateTimeField()


class ScriptInclusion(BaseModel):
    script = ForeignKeyField(Script, backref="script_inclusions")
    document_inclusion = ForeignKeyField(DocumentInclusion, backref="script_inclusions")


####### Helper Functions ##############################################################################################


def get_parent_frames(frame: Frame) -> List[str]:
    """
    Get a list of all parent frames from a Playwright frame instance.

    :param frame: Playwright Frame object
    :return: List of parent frames
    """
    parent_list = []
    while frame.parent_frame is not None:
        frame = frame.parent_frame
        parent_list.append(frame.url)
    return parent_list


def hash_sha1(x: bytes) -> str:
    """
    Hashes the content of a document or script.

    :param x: Content of the document or script
    :return: Hash of the content
    """
    return hashlib.sha1(x).hexdigest()


def create_path_from_hash(hash_str: str) -> str:
    """
    Creates and returns a file system path according to a given document or script hash.
    For a script with the hash **3f4a** the path **./file_storage/3/f/4/a** would be created and returned.

    :param hash_str: Hash of the file we want to store
    :return: Created file path
    """
    dir_path_parts = list(hash_str[:-1])
    file_name = hash_str[-1]
    dir_path = os.path.join("./file_storage/", *dir_path_parts)
    os.makedirs(dir_path, exist_ok=True)
    file_path = os.path.join(dir_path, file_name)
    return file_path


def store_and_hash_content(response: Response) -> str:
    """
    Stores the content of a response according to its hash and returns the hash.

    :param response: Playwright Response object
    :return: Hash of the stored content
    """
    content = response.body()
    hashed = hash_sha1(content)
    with open(create_path_from_hash(hashed), 'wb') as f:
        f.write(content)
    return hashed


class FrameHierarchy:
    """
    The class is used to build a frame hierarchy of the iframes loaded on the currently crawled site by containing
    all information about the frame, its documents, scripts and references to the children frames.
    """

    def __init__(self, url, sha1):
        self.url = url
        self.sha1 = sha1
        self.visited = datetime.now().now()
        self.children = {}
        self.scripts = []

    def add_children(self, child):
        self.children[child.url] = child

    def add_script(self, script):
        self.scripts.append(script)

    def find_child(self, parent_list):
        """
        Tries to find a child with the given parents in the frame hierarchy of the instance.
        If it is found the FrameHierarchy instance is returned.

        :param parent_list: List of all parents of the frame
        :return: The found FrameHierarchy instance - None if not found
        """
        try:
            curr_frame = self
            for parent in reversed(parent_list[:-1]):
                curr_frame = curr_frame.children[parent]
            return curr_frame
        except KeyError:
            return None

    def __str__(self) -> str:
        return self.string_helper()

    def string_helper(self, level=0) -> str:
        result = "\t" * level + self.url + "\n" + "\t" * (level+1) + "Scripts: " + str(self.scripts) + "\n"
        if self.children is not None:
            for child in self.children.values():
                result += child.string_helper(level=level + 1)
        return result


####### Module Implementation #########################################################################################


class StorageAccessApi(Module):
    @staticmethod
    def register_job(log: Logger) -> None:
        log.info('Create tables for StorageAccessApi module')
        with database:
            database.create_tables([Document, DocumentInclusion, Script, ScriptInclusion])

    def add_handlers(self, url: URL) -> None:
        super().add_handlers(url)

        def handle_response(response: Response):
            """
            Handles all responses that are received during the page visit.
            The function retrieves the content of documents and scripts to store them in the file system.
            It also collects further information about the documents, scripts and their frames and stores them in the
            FrameHierarchy class.

            :param response: Playwright Response object
            :return: None
            """
            try:
                # Check if response is a script and that it was not a redirect
                if response.request.resource_type == 'script' and response.ok:
                    script_hash = store_and_hash_content(response)
                    parent_list = [response.frame.url] + get_parent_frames(frame=response.frame)
                    parent_frame = self.top_level.find_child(parent_list)
                    if parent_frame is None:
                        raise Exception("Parent frame was not found!")
                    # TODO Implement string matching to populate the SAA parameter
                    parent_frame.add_script({
                        "sha1": script_hash, "url": response.url, "saa": False
                    })
                # Check if response is a document and that it was not a redirect
                elif response.request.resource_type == 'document' and response.ok:
                    # TODO Implement string matching to populate the SAA parameter
                    # Check if the document is the top-level site or loaded in an iframe
                    if response.frame.parent_frame is None:
                        document_hash = store_and_hash_content(response)
                        self.top_level = FrameHierarchy(url=response.url, sha1=document_hash)
                    else:
                        document_hash = store_and_hash_content(response)
                        parent_list = get_parent_frames(frame=response.frame)
                        parent_frame = self.top_level.find_child(parent_list)
                        if parent_frame is None:
                            raise Exception("Parent frame was not found!")
                        parent_frame.add_children(FrameHierarchy(url=response.url, sha1=document_hash))
            except Exception:
                self.crawler.log.error(f"Error handling response {response.url}: {traceback.print_exc()}")

        def store_collected_data():
            """
            Stores all the retrieved information about the documents, scripts and their frames in the database.
            The data is taken from the FrameHierarchy object where it is stored temporarily during the page visit.

            :return: None
            """
            # TODO Store all the scripts and HTML documents if SAA is used
            pass

        # Register response handler
        self.crawler.page.on("response", handle_response)
        # Register closing handler that executes before the site is changed
        # Crawler waits until the handler finished executing
        self.crawler.page.on("close", store_collected_data)

    def receive_response(self, responses: List[Optional[Response]], url: URL, final_url: str, start: List[datetime],
                         repetition: int) -> None:
        super().receive_response(responses, url, final_url, start, repetition)

