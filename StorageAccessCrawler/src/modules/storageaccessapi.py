import hashlib
import os
import traceback
from datetime import datetime
from logging import Logger
from typing import List, Optional

from playwright.sync_api import Response, Frame, Request
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
    parent = ForeignKeyField("self", null=True, backref="children")  # Top-level if parent is 'null'
    crawl_date = DateTimeField()


class ScriptInclusion(BaseModel):
    script = ForeignKeyField(Script, backref="script_inclusions")
    document_inclusion = ForeignKeyField(DocumentInclusion, backref="script_inclusions")


####### Helper Functions ##############################################################################################


def get_parent_frames(frame: Frame, script_frame: Frame = None) -> List[str]:
    """
    Get a list of all parent frames from a Playwright frame instance.

    :param frame: Playwright Frame object
    :param script_frame: Script frame that need to be prepended
    :return: List of parent frames
    """
    if script_frame is not None and script_frame.url != "about:blank":
        parent_list = [script_frame.url.split("#")[0]]
    else:
        parent_list = []
    while frame.parent_frame is not None:
        frame = frame.parent_frame
        if frame.url != "about:blank":
            parent_list.append(frame.url.split("#")[0])
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


def store_file(hashed: str, content: bytes, logger: Logger):
    """
    Stores the content of a document or script in the file system.

    :param hashed: Hash of the document or script
    :param content: Content of the document or script
    :param logger: Logger object to log to the crawler logs
    :return: None
    """
    try:
        with open(create_path_from_hash(hashed), 'xb') as f:
            f.write(content)
    # If file exists do not write it again
    except FileExistsError:
        logger.info(f"File with hash {hashed} already exists")


class FrameHierarchy:
    """
    The class is used to build a frame hierarchy of the iframes loaded on the currently crawled site by containing
    all information about the frame, its documents, scripts and references to the children frames.
    """

    def __init__(self, url, sha1, content, saa):
        self.url = url
        self.sha1 = sha1
        self.content = content
        self.visited = datetime.now().now()
        self.children = {}
        self.scripts = []
        self.saa = saa

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
        result = "\t" * level + self.url + " / saa: " + str(self.saa) + "\n"
        if self.children is not None:
            for child in self.children.values():
                result += child.string_helper(level=level + 1)
        return result


def store_site_data_db(frame: FrameHierarchy,
                       logger: Logger,
                       top_level_document: Document = None,
                       parent_document_inclusion: DocumentInclusion = None):
    """
    Takes the frame hierarchy and recursively stores all collected information about the site in the database.
    The content of the documents or scripts instead is stored in the file system beforehand
    and the location can be retrieved through the hash. Example: **3f4a** has the path **./file_storage/3/f/4/a**

    :param frame: Frame hierarchy
    :param logger: Logging instance to write to the crawler logs
    :param top_level_document: Top-level document DB object
    :param parent_document_inclusion: Parent frame in the hierarchy
    :return: None
    """

    document, created = Document.get_or_create(
        sha1=frame.sha1,
        defaults={'url': frame.url, 'saa': frame.saa}
    )
    store_file(frame.sha1, frame.content, logger)

    document_inclusion = DocumentInclusion.create(
        document=document,
        top_level_site=top_level_document if top_level_document else document,
        parent=parent_document_inclusion,
        crawl_date=frame.visited
    )

    for script in frame.scripts:
        script_obj, created = Script.get_or_create(
            sha1=script['sha1'],
            defaults={'url': script['url'], 'saa': script['saa']}
        )
        store_file(script['sha1'], script['content'], logger)
        ScriptInclusion.create(
            script=script_obj,
            document_inclusion=document_inclusion
        )

    for child_url, child_frame in frame.children.items():
        store_site_data_db(
            child_frame,
            logger,
            top_level_document if top_level_document else document,
            document_inclusion
        )


####### Module Implementation #########################################################################################


class StorageAccessApi(Module):

    def __init__(self, crawler) -> None:
        super().__init__(crawler)
        self.saa_found = False

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
                if ((response.request.resource_type == 'script' or response.request.resource_type == 'document')
                        and response.ok):
                    # Wait until the DOM content of every parent frame was loaded
                    frame = response.frame
                    # Exclude dynamically added scripts as the "domcontentloaded" state would never be reached
                    while frame is not None and frame.url != "":
                        frame.wait_for_load_state("domcontentloaded")
                        frame = frame.parent_frame

                # Check if response is a script and that it was not a redirect
                if response.request.resource_type == 'script' and response.ok:
                    script_hash, script_content, saa = self.hash_content(response)
                    parent_list = get_parent_frames(frame=response.frame, script_frame=response.frame)
                    parent_frame = self.top_level.find_child(parent_list)
                    if parent_frame is None:
                        raise Exception(f"Script frame was not found!: {parent_list} - {self.top_level}")
                    parent_frame.add_script({
                        "sha1": script_hash, "url": response.url, "content": script_content, "saa": saa
                    })
                # Check if response is a document and that it was not a redirect
                elif response.request.resource_type == 'document' and response.ok:
                    # Check if the document is the top-level site or loaded in an iframe
                    if response.frame.parent_frame is None:
                        document_hash, document_content, saa = self.hash_content(response)
                        self.top_level = FrameHierarchy(url=response.url, sha1=document_hash,
                                                        content=document_content, saa=saa)
                    else:
                        document_hash, document_content, saa = self.hash_content(response)
                        parent_list = get_parent_frames(frame=response.frame)
                        parent_frame = self.top_level.find_child(parent_list)
                        if parent_frame is None:
                            raise Exception(f"Document frame was not found!: {parent_list} - {self.top_level}")
                        parent_frame.add_children(FrameHierarchy(url=response.url, sha1=document_hash,
                                                                 content=document_content, saa=saa))
            except Exception:
                self.crawler.log.error(f"Error handling response {response.url}: {traceback.format_exc()}")

        def store_collected_data():
            """
            Stores all the retrieved information about the documents, scripts and their frames in the database.
            The data is taken from the FrameHierarchy object where it is stored temporarily during the page visit.

            :return: None
            """
            if self.saa_found:
                store_site_data_db(self.top_level, logger=self.crawler.log)

        # Register response handler
        self.crawler.page.on("response", handle_response)
        # Register closing handler that executes before the site is changed
        # Crawler waits until the handler finished executing
        self.crawler.page.on("close", store_collected_data)

    def receive_response(self, responses: List[Optional[Response]], url: URL, final_url: str, start: List[datetime],
                         repetition: int) -> None:
        super().receive_response(responses, url, final_url, start, repetition)


####### Module Helper Functions #######################################################################################


    def hash_content(self, response: Response) -> (str, bytes, bool):
        """
        Calculates the hash of a script or document and returns the hash and the content.
        Also performs string matching for SAA functions on content and updates the module field **saa_found**
        if it matches and returns a third value that indicates whether SAA was used in the document or script.

        :param response: Playwright Response object
        :return: Hash and content of the Response, whether SAA function were found with string matching
        """
        content = response.body()
        saa = False
        if b"hasStorageAccess" in content or b"requestStorageAccess" in content:
            saa = True
            self.saa_found = True
        hashed = hash_sha1(content)
        return hashed, content, saa

