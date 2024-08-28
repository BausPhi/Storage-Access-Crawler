import hashlib
import os
import random
import re
import string
import traceback
from config import Config
from datetime import datetime
from logging import Logger
from typing import List, Optional

from playwright.sync_api import Response, Frame
from playwright._impl._errors import TargetClosedError, Error
from peewee import ForeignKeyField, TextField, BooleanField, DateTimeField

from database import URL, database, BaseModel, Task
from modules.module import Module


####### Database Models ###############################################################################################


class Document(BaseModel):
    sha1 = TextField(unique=True)
    has_saa = BooleanField(default=False)
    request_saa = BooleanField(default=False)
    saa_for = BooleanField(default=False)


class Script(BaseModel):
    sha1 = TextField(unique=True)
    has_saa = BooleanField(default=False)
    request_saa = BooleanField(default=False)
    saa_for = BooleanField(default=False)


class DocumentInclusion(BaseModel):
    document = ForeignKeyField(Document, backref="document_inclusions")
    url = TextField()
    top_level_site = ForeignKeyField(Document)
    top_level_url = TextField()
    parent = ForeignKeyField("self", null=True, backref="children")  # Top-level if parent is "null"
    site = TextField()
    browser = TextField()
    job = TextField()


class ScriptInclusion(BaseModel):
    script = ForeignKeyField(Script, backref="script_inclusions")
    url = TextField()
    top_level_site = ForeignKeyField(Document)
    top_level_url = TextField()
    document_inclusion = ForeignKeyField(DocumentInclusion, backref="script_inclusions")
    document_inclusion_url = TextField()
    site = TextField()
    browser = TextField()
    job = TextField()


class SaaCall(BaseModel):
    top_level_url = TextField()
    document_url = TextField()
    site = TextField()
    has_saa = BooleanField(default=False)
    request_saa = BooleanField(default=False)
    saa_for = BooleanField(default=False)
    job = TextField()

    # Make entries unique by top_level_url and document_url
    class Meta:
        indexes = ((('top_level_url', 'document_url', 'job'), True),)


####### Helper Functions ##############################################################################################


def get_parent_frames(frame: Frame, script_frame: bool = False) -> List[str]:
    """
    Get a list of all parent frames from a Playwright frame instance.

    :param frame: Playwright Frame object
    :param script_frame: Script frame that need to be prepended
    :return: List of parent frames
    """
    parent_list = []
    if script_frame:
        parent_list = [frame.url.split("#")[0]]
    while frame.parent_frame is not None:
        frame = frame.parent_frame
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
    dir_path_parts = list(hash_str)
    dir_path = os.path.join("./file_storage/", *dir_path_parts)
    os.makedirs(dir_path, exist_ok=True)
    file_path = os.path.join(dir_path, hash_str)
    return file_path


def store_file(hashed: str, content: bytes):
    """
    Stores the content of a document or script in the file system.

    :param hashed: Hash of the document or script
    :param content: Content of the document or script
    :param name: Name of the resource file
    :return: None
    """
    try:
        with open(create_path_from_hash(hashed), "xb") as f:
            f.write(content)
    # If file exists do not write it again
    except FileExistsError:
        pass


class FrameHierarchy:
    """
    The class is used to build a frame hierarchy of the iframes loaded on the currently crawled site by containing
    all information about the frame, its documents, scripts and references to the children frames.
    """

    def __init__(self, url, sha1, content, has_saa=False, request_saa=False, saa_for=False):
        self.url = url
        self.sha1 = sha1
        self.content = content
        self.visited = datetime.now().now()
        self.children = {}
        self.scripts = []
        self.has_saa = has_saa
        self.request_saa = request_saa
        self.saa_for = saa_for

    def add_children(self, child):
        if child.url in self.children:
            children = self.children[child.url].children
            scripts = self.children[child.url].scripts
            self.children[child.url] = child
            self.children[child.url].children = children
            self.children[child.url].scripts = scripts
        else:
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
        curr_frame = self
        for parent in reversed(parent_list[:-1]):
            if parent == "" or parent == "about:srcdoc" or parent == "about:blank":
                continue
            if parent in curr_frame.children:
                curr_frame = curr_frame.children[parent]
            else:
                curr_frame.add_children(FrameHierarchy(url=parent, sha1="undefined", content=b"undefined"))
                curr_frame = curr_frame.children[parent]
        return curr_frame

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
                       site: str,
                       browser: str,
                       job_id: str,
                       top_level_document: Document = None,
                       top_level_url: str = None,
                       parent_document_inclusion: DocumentInclusion = None):
    """
    Takes the frame hierarchy and recursively stores all collected information about the site in the database.
    The content of the documents or scripts instead is stored in the file system beforehand
    and the location can be retrieved through the hash. Example: **3f4a** has the path **./file_storage/3/f/4/a**

    :param frame: Frame hierarchy
    :param logger: Logging instance to write to the crawler logs
    :param site: Domain of the site that was crawled
    :param browser: Browser that was used for the crawl
    :param job_id: Current crawler job
    :param top_level_document: Top-level document DB object
    :param top_level_url: URL of the top-level site
    :param parent_document_inclusion: Parent frame in the hierarchy
    :return: None
    """
    document, created = Document.get_or_create(
        sha1=frame.sha1,
        defaults={"has_saa": frame.has_saa, "request_saa": frame.request_saa,
                  "saa_for": frame.saa_for}
    )
    current_url = frame.url
    store_file(frame.sha1, frame.content)

    document_inclusion = DocumentInclusion.create(
        document=document,
        top_level_site=top_level_document if top_level_document else document,
        top_level_url=top_level_url if top_level_url else current_url,
        parent=parent_document_inclusion,
        site=site,
        browser=browser,
        url=frame.url,
        job=job_id
    )

    for script in frame.scripts:
        script_obj, created = Script.get_or_create(
            sha1=script["sha1"],
            defaults={"has_saa": script["has_saa"], "request_saa": script["request_saa"],
                      "saa_for": script["saa_for"]}
        )
        store_file(script["sha1"], script["content"])
        ScriptInclusion.create(
            script=script_obj,
            top_level_site=top_level_document if top_level_document else document,
            top_level_url=top_level_url if top_level_url else current_url,
            document_inclusion=document_inclusion,
            document_inclusion_url=current_url,
            site=site,
            browser=browser,
            url=script["url"],
            job=job_id
        )

    for child_url, child_frame in frame.children.items():
        store_site_data_db(
            child_frame,
            logger,
            site,
            browser,
            job_id,
            top_level_document if top_level_document else document,
            top_level_url if top_level_url else current_url,
            document_inclusion
        )


####### Module Implementation #########################################################################################


class StorageAccessApi(Module):

    def __init__(self, crawler) -> None:
        super().__init__(crawler)
        self.saa_found = False
        self.top_level = FrameHierarchy(url="", sha1="undefined",
                                        content=b"undefined")

    @staticmethod
    def register_job(log: Logger) -> None:
        log.info("Create tables for StorageAccessApi module")
        with database:
            database.create_tables([Document, DocumentInclusion, Script, ScriptInclusion, SaaCall])

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
                # Do not handle responses with specific status code
                if not response.ok or response.status == 204:
                    return

                # Check if response is a script and that it was not a redirect
                if response.request.resource_type == "script":
                    script_hash, script_content, has_saa, request_saa, saa_for = self.hash_content(response)
                    parent_list = get_parent_frames(frame=response.frame, script_frame=True)
                    parent_frame = self.top_level.find_child(parent_list)
                    parent_frame.add_script({
                        "sha1": script_hash, "url": response.url, "content": script_content, "has_saa": has_saa,
                        "request_saa": request_saa, "saa_for": saa_for
                    })
                # Check if response is a document and that it was not a redirect
                elif response.request.resource_type == "document":
                    # Check if the document is the top-level site or loaded in an iframe
                    if response.frame.parent_frame is None:
                        document_hash, document_content, has_saa, request_saa, saa_for = self.hash_content(response)
                        stored_scripts, stored_children = self.top_level.scripts, self.top_level.children
                        self.top_level = FrameHierarchy(url=response.url, sha1=document_hash,
                                                        content=document_content, has_saa=has_saa,
                                                        request_saa=request_saa, saa_for=saa_for)
                        self.top_level.children = stored_children
                        self.top_level.scripts = stored_scripts
                    else:
                        document_hash, document_content, has_saa, request_saa, saa_for = self.hash_content(response)
                        parent_list = get_parent_frames(frame=response.frame)
                        parent_frame = self.top_level.find_child(parent_list)
                        parent_frame.add_children(FrameHierarchy(url=response.url, sha1=document_hash,
                                                                 content=document_content, has_saa=has_saa,
                                                                 request_saa=request_saa, saa_for=saa_for))
            except TargetClosedError:
                self.crawler.log.warning(f"Problem handling response {response.url}: Target page was already closed")
            except Error as e:
                if "identifier" in e.message:
                    self.crawler.log.warning(
                        f"Problem handling response {response.url}: Page was redirected, response not available"
                    )
            except Exception:
                self.crawler.log.error(f"Error handling response {response.url}: {traceback.format_exc()}")

        def perform_user_actions():
            """
            Performs random user actions to increase the probability of triggering SAA functions. This is done because
            if no access was granted to the site before, requests must be preceded by a user interaction in order to get
            access. Therefore, sites might only call the API after a user interaction.

            :return: None
            """
            try:
                def handle_route(route):
                    request = route.request
                    # Check if the request is a top-level navigation request
                    if request.is_navigation_request() and request.frame == self.crawler.page.main_frame:
                        route.abort()
                    else:
                        route.continue_()

                # Prevent top-level navigations
                self.crawler.page.route("**", handle_route)

                def interact_with_frames_recursively(frame):
                    # Click a button
                    buttons = frame.locator('button')
                    num_buttons = buttons.count()
                    for i in range(num_buttons):
                        button = buttons.nth(i)
                        button.scroll_into_view_if_needed()
                        button.click()

                    # Scroll in the iframes
                    scroll_y = self.crawler.page.evaluate("() => document.body.scrollHeight")
                    scroll_x = self.crawler.page.evaluate("() => document.body.scrollWidth")
                    self.crawler.page.mouse.wheel(scroll_x, scroll_y)

                    # Recursively interact with all child frames
                    for child_frame in frame.child_frames:
                        interact_with_frames_recursively(child_frame)

                frames = self.crawler.page.frames
                for iframe in frames:
                    if iframe == self.crawler.page.main_frame:
                        print("Main Frame!")
                        continue
                    interact_with_frames_recursively(iframe)
            except Exception:
                self.crawler.log.warning(f"Some user interaction failed!")

        def store_collected_data():
            """
            Stores all the retrieved information about the documents, scripts and their frames in the database.
            The data is taken from the FrameHierarchy object where it is stored temporarily during the page visit.

            :return: None
            """
            if self.saa_found:
                store_site_data_db(self.top_level, logger=self.crawler.log, site=self.crawler.task.site,
                                   browser=Config.BROWSER, job_id=self.crawler.job_id)
            self.top_level = FrameHierarchy(url="", sha1="undefined", content=b"undefined")
            self.saa_found = False

        def handle_storage_access_api_called(function, document_url):
            """
            Handle when a Storage Access API function was called

            :param function: SAA function that was called
            :param document_url: Document that called the function
            :return: None
            """
            while not self.top_level:
                pass
            call_object, created = SaaCall.get_or_create(
                top_level_url=self.top_level.url,
                document_url=document_url,
                job=self.crawler.job_id,
                defaults={"site": self.crawler.task.site, "has_saa": function == "hasStorageAccess",
                          "request_saa": function == "requestStorageAccess",
                          "saa_for": function == "requestStorageAccessFor"}
            )
            if not created:
                call_object.has_saa = function == "hasStorageAccess" if not call_object.has_saa else call_object.has_saa
                call_object.request_saa = function == "requestStorageAccess" if not call_object.request_saa else call_object.request_saa
                call_object.saa_for = function == "requestStorageAccessFor" if not call_object.saa_for else call_object.saa_for
                call_object.save()

        def inject_js(page):
            """
            Inject Storage Access API hooking script into webpage

            :param page: Page object to inject script into
            :return: None
            """
            page.add_init_script(path="./resources/hook_api_calls.js")

        # Register response handler to intercept documents and scripts
        self.crawler.page.on("response", handle_response)
        # Register closing handler that executes before the site is changed
        # Crawler waits until the handler finished executing
        self.crawler.page.on("close", store_collected_data)
        # Perform random user actions once the page finished loading
        # ATTENTION: Disable when crawling with Firefox as it leads to errors
        self.crawler.page.on("load", perform_user_actions)
        # Register onload event handler to inject script for function hooking
        self.crawler.page.on("load", inject_js(self.crawler.page))
        # Expose the Storage Access API call handler to the page
        self.crawler.page.expose_function("sa_call_handler", handle_storage_access_api_called)

    def receive_response(self, responses: List[Optional[Response]], url: URL, final_url: str, start: List[datetime],
                         repetition: int) -> None:
        super().receive_response(responses, url, final_url, start, repetition)


####### Module Helper Functions #######################################################################################


    def hash_content(self, response: Response) -> (str, bytes, bool, bool, bool):
        """
        Calculates the hash of a script or document and returns the hash and the content.
        Also performs string matching for SAA functions on content and updates the module field **saa_found**
        if it matches and returns whether SAA were used in the document or script.

        :param response: Playwright Response object
        :return: Hash and content of the Response, whether SAA functions were found with string matching
        """
        content = response.body()
        has_saa, request_saa, saa_for = False, False, False
        try:
            if re.search(pattern=Config.STRING_MATCHING_HAS_SAA, string=content.decode()) is not None:
                has_saa = True
                self.saa_found = True
            if re.search(pattern=Config.STRING_MATCHING_REQUEST_SAA, string=content.decode()) is not None:
                request_saa = True
                self.saa_found = True
            if re.search(pattern=Config.STRING_MATCHING_SAA_FOR, string=content.decode()) is not None:
                saa_for = True
                self.saa_found = True
        except UnicodeDecodeError:
            self.crawler.log.warning("Response Data was not UTF-8 decodable!")
        hashed = hash_sha1(content)
        return hashed, content, has_saa, request_saa, saa_for
