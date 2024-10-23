import hashlib
import os
import random
import re
import string
import traceback
import datetime
from config import Config
from datetime import datetime
from http.cookies import SimpleCookie
from logging import Logger
from typing import List, Optional, Dict
from utils import get_domain_from_url

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
    landing_page = BooleanField()


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
    landing_page = BooleanField()


class SaaCall(BaseModel):
    top_level_url = TextField()
    document_url = TextField()
    site = TextField()
    has_saa = BooleanField(default=False)
    request_saa = BooleanField(default=False)
    saa_for = BooleanField(default=False)
    job = TextField()
    landing_page = BooleanField()

    # Make entries unique by top_level_url and document_url
    class Meta:
        indexes = ((('top_level_url', 'document_url', 'job'), True),)


class Cookies(BaseModel):
    name = TextField()
    domain = TextField()
    path = TextField()
    expires = DateTimeField()
    secure = BooleanField
    sameSite = TextField()
    httponly = BooleanField()
    site = TextField()
    job = TextField()

    # Make cookie unique by name, site and job
    class Meta:
        indexes = ((('name', 'site', 'job'), True),)


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
    :return: None
    """
    try:
        with open(create_path_from_hash(hashed), "xb") as f:
            f.write(content)
    # If file exists do not write it again
    except FileExistsError:
        pass


def parse_cookie_attributes(parsed_cookie: SimpleCookie) -> (str, Dict[str, str]):
    """
    Parses cookie attributes from SimpleCookie object.

    :param parsed_cookie: SimpleCookie object
    :return: Dictionary of cookie attributes and name of cookie
    """
    key_list = list(parsed_cookie.keys())
    if len(key_list) > 0:
        name = key_list[0]
        return name, parsed_cookie[name]
    else:
        return "", None


def store_cookies(cookies: list[SimpleCookie], site: str, job: str):
    """
    Stores cookies in the database

    :param cookies: List of cookie objects
    :param site: Site that was visited when the cookie was stored
    :param job: Current crawling job
    :return:
    """
    for cookie in cookies:
        Cookies.get_or_create(
            name=cookie["name"],
            site=site,
            job=job,
            defaults={
                "domain": cookie["domain"],
                "path": cookie["path"],
                "expires": datetime.fromtimestamp(cookie["expires"]),
                "httponly": cookie["httpOnly"],
                "secure": cookie["secure"],
                "sameSite": cookie["sameSite"]
            }
        )


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
        self.cookies = []

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


def store_site_data_db(frame: FrameHierarchy,
                       logger: Logger,
                       site: str,
                       browser: str,
                       job_id: str,
                       landing_page: bool,
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
    :param landing_page: Whether the current page is a landing page
    :param top_level_document: Top-level document DB object
    :param top_level_url: URL of the top-level site
    :param parent_document_inclusion: Parent frame in the hierarchy
    :return: None
    """
    if frame.has_saa or frame.request_saa or frame.saa_for:
        document, created = Document.get_or_create(
            sha1=frame.sha1,
            defaults={"has_saa": frame.has_saa, "request_saa": frame.request_saa,
                      "saa_for": frame.saa_for}
        )
        store_file(frame.sha1, frame.content)
        if frame.request_saa:
            site_new_task = get_domain_from_url(frame.url)
            url_new_task = f"https://{site_new_task}"
            if not Task.select().where(
                (Task.site == site_new_task) & (Task.job == job_id)
            ).exists():
                Task.create(job=job_id, site=site_new_task, url=url_new_task,
                            landing_page=url_new_task, rank=100001, note="cookies")
    else:
        document, created = Document.get_or_create(
            sha1="dummy_document_for_non_saa_inclusions",
            defaults={"has_saa": False, "request_saa": False,
                      "saa_for": False}
        )
    current_url = frame.url

    document_inclusion = DocumentInclusion.create(
        document=document,
        top_level_site=top_level_document if top_level_document is not None else document,
        top_level_url=top_level_url if top_level_url is not None else current_url,
        parent=parent_document_inclusion,
        site=site,
        browser=browser,
        url=frame.url,
        job=job_id,
        landing_page=landing_page,
    )

    for script in frame.scripts:
        if script["has_saa"] or script["request_saa"] or script["saa_for"]:
            script_obj, created = Script.get_or_create(
                sha1=script["sha1"],
                defaults={"has_saa": script["has_saa"], "request_saa": script["request_saa"],
                          "saa_for": script["saa_for"]}
            )
            store_file(script["sha1"], script["content"])
            ScriptInclusion.create(
                script=script_obj,
                top_level_site=top_level_document if top_level_document is not None else document,
                top_level_url=top_level_url if top_level_url is not None else current_url,
                document_inclusion=document_inclusion,
                document_inclusion_url=current_url,
                site=site,
                browser=browser,
                url=script["url"],
                job=job_id,
                landing_page=landing_page,
            )
            if script["request_saa"]:
                site_new_task = get_domain_from_url(current_url)
                url_new_task = f"https://{site_new_task}"
                if not Task.select().where(
                    (Task.site == site_new_task) & (Task.job == job_id)
                ).exists():
                    Task.create(job=job_id, site=site_new_task, url=url_new_task,
                                landing_page=url_new_task, rank=100001, note="cookies")

    for child_url, child_frame in frame.children.items():
        store_site_data_db(
            child_frame,
            logger,
            site,
            browser,
            job_id,
            landing_page,
            top_level_document if top_level_document is not None else document,
            top_level_url if top_level_url is not None else current_url,
            document_inclusion
        )


####### Module Implementation #########################################################################################


class StorageAccessApi(Module):

    def __init__(self, crawler) -> None:
        super().__init__(crawler)
        self.saa_found = False
        self.top_level = FrameHierarchy(url="", sha1="undefined",
                                        content=b"undefined")
        self.landing_visited = ""

    @staticmethod
    def register_job(log: Logger) -> None:
        log.info("Create tables for StorageAccessApi module")
        with database:
            database.create_tables([Document, DocumentInclusion, Script, ScriptInclusion, SaaCall, Cookies])

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
                # Get cookies stored for top-level site
                for cookie in self.crawler.context.cookies():
                    if self.top_level is not None and cookie not in self.top_level.cookies:
                        self.top_level.cookies.append(cookie)

                # Do not handle responses with non-ok status code and status 204
                # Exclude the top-level document from this
                if not (response.request.resource_type == "document" and response.frame.parent_frame is None):
                    if not response.ok or response.status == 204:
                        return

                # Check if response is a script and that it was not a redirect
                if response.request.resource_type == "script":
                    script_hash, script_content, has_saa, request_saa, saa_for = self.hash_content(response)
                    parent_list = get_parent_frames(frame=response.frame, script_frame=True)
                    parent_frame = self.top_level.find_child(parent_list)
                    parent_frame.add_script({
                        "sha1": script_hash, "url": response.url, "content": script_content, "has_saa": has_saa,
                        "request_saa": request_saa, "saa_for": saa_for,
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
                        self.current_url = self.crawler.currenturl
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
            access. Therefore, sites might only call the API after a user interaction. Also, this might yield
            better crawl results.

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

                # Get viewport dimensions
                viewport = self.crawler.page.viewport_size
                width, height = viewport["width"], viewport["height"]

                # Scroll for random amount
                self.crawler.page.evaluate(f"window.scrollBy(0, {random.randint(0, 200)});")
                self.crawler.page.evaluate(f"window.scrollBy({random.randint(0, 200)}, 0);")

                # Press random keys
                keys = (list(string.ascii_lowercase) + list(string.digits) +
                        ["ArrowDown", "ArrowUp", "ArrowLeft", "ArrowRight", "Enter"])
                for _ in range(random.randint(0, 5)):
                    self.crawler.page.keyboard.press(random.choice(keys))

                # Make a random mouse click
                self.crawler.page.mouse.click(x=random.randint(0, width - 1), y=random.randint(0, height - 1),
                                              button="left", delay=10)
            except Exception:
                self.crawler.log.warning(f"Some user interaction failed!")

        def store_collected_data():
            """
            Stores all the retrieved information about the documents, scripts and their frames in the database.
            The data is taken from the FrameHierarchy object where it is stored temporarily during the page visit.

            :return: None
            """
            site = self.crawler.task.site
            if self.saa_found and self.crawler.task.note != "cookies":
                store_site_data_db(self.top_level, logger=self.crawler.log, site=site,
                                   browser=Config.BROWSER, job_id=self.crawler.job_id,
                                   landing_page=self.landing_visited != site)
            if self.crawler.task.note == "cookies":
                store_cookies(self.top_level.cookies, site, self.crawler.job_id)
            self.top_level = FrameHierarchy(url="", sha1="undefined", content=b"undefined")
            self.saa_found = False
            self.landing_visited = site

        def handle_storage_access_api_called(function, document_url):
            """
            Handle when a Storage Access API function was called

            :param function: SAA function that was called
            :param document_url: Document that called the function
            :return: None
            """
            while not self.top_level:
                pass
            site = self.crawler.task.site
            call_object, created = SaaCall.get_or_create(
                top_level_url=self.top_level.url,
                document_url=document_url,
                job=self.crawler.job_id,
                defaults={"site": site, "has_saa": function == "hasStorageAccess",
                          "request_saa": function == "requestStorageAccess",
                          "saa_for": function == "requestStorageAccessFor",
                          "landing_page": self.landing_visited != site}
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
        # self.crawler.page.on("load", perform_user_actions)

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
