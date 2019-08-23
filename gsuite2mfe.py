import argparse
import dateparser
import inspect
import json
import logging
import logging.config
import pickle
import os
import socket
import sys

from configparser import NoOptionError, ConfigParser
from datetime import datetime, timedelta, timezone
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

""" G Suite/Google Apps Events -> McAfee ESM

This will pull events from G Suite (formerly Google Apps) and forward
the events to a McAfee ESM (or any syslog destination).

The script requires Python 3 and was tested with 3.5.4 for Windows
and Linux.

The script requires a config.ini file for the Receiver IP and port. An
alternate config file can be specified from the command line.

An example config.ini is available at:
https://raw.githubusercontent.com/andywalden/gsuite2ESM/config.ini

This script is intended to be called as a cron task. A bookmark file is
created in the same directory. If the bookmark file does not exist, one
will be created and future events will be forwarded.

Make sure the permissions on the config.ini file are secure as not to expose
any credentials.

"""

__author__ = "Andy Walden"
__version__ = "1.0.1b"


class Args(object):
    """
    Handles any args and passes them back as a dict
    """

    def __init__(self, args):
        log_levels = ["quiet", "error", "warning", "info", "debug"]
        formatter_class = argparse.RawDescriptionHelpFormatter
        parser = argparse.ArgumentParser(
            formatter_class=formatter_class,
            description="Send Google GSuite events to McAfee ESM",
        )
        self.args = args

        parser.add_argument(
            "-s",
            "--start",
            dest="s_time",
            metavar="",
            help=(
                "Set start time to retrieve events." "Format: 2019-04-26T00:00:00.000Z"
            ),
        )

        parser.add_argument(
            "-e",
            "--end",
            dest="e_time",
            metavar="",
            help="Set end time to retrieve events. Format: 2019-04-29T12:53:38.000Z",
        )

        parser.add_argument(
            "-t",
            "--test",
            action="store_true",
            default=False,
            dest="testmode",
            help="Disable syslog forwarding. Combine with -l debug for console output",
        )

        parser.add_argument(
            "-w",
            "--write",
            action="store_true",
            default=False,
            dest="write_eventfile",
            help="Write events to log: gsuite2mfe_events.log. Use -f to change path/filename",
        )

        parser.add_argument(
            "-f",
            "--file",
            dest="event_filename",
            metavar="",
            help="Specify alternate path/filename for -w option",
        )

        parser.add_argument(
            "-v",
            "--version",
            action="version",
            help="Show version",
            version="%(prog)s {}".format(__version__),
        )

        parser.add_argument(
            "-l",
            "--level",
            choices=log_levels,
            metavar="",
            help="Logging output level. Default: warning",
        )

        parser.add_argument(
            "-c",
            "--config",
            dest="cfgfile",
            metavar="",
            help="Path to config file. Default: config.ini",
        )

        self.pargs = parser.parse_args()

    def get_args(self):
        return self.pargs


class Config(object):
    """ Creates object for provided configfile/section settings """

    def __init__(self, filename, header):
        config = ConfigParser()
        cfgfile = config.read(filename)
        if not cfgfile:
            raise ValueError("Config file not found:", filename)
        self.__dict__.update(config.items(header))


def logging_init():
    filename = get_filename()
    logfile = filename + ".log"
    hostname = socket.gethostname()
    formatter = logging.Formatter(
        "%(asctime)s {} %(module)s: %(message)s".format(hostname),
        datefmt="%b %d %H:%M:%S",
    )
    logger = logging.getLogger()
    fh = logging.FileHandler(logfile, mode="a")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logging.getLogger("googleapiclient").setLevel(logging.CRITICAL)


def get_filename():
    filename = (inspect.getfile(inspect.currentframe()).split("\\", -1)[-1]).rsplit(".", 1)[0]
    return filename


class Syslog(object):
    """
    Open TCP socket using supplied server IP and port.

    Returns socket or None on failure
    """

    def __init__(self, server, port=514):
        logging.debug("Initializing syslog server: %s:%s", server, port)
        port = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.connect((server, port))
        except socket.timeout:
            logging.error("Connection timeout to syslog: %s", server)
            raise
        except socket.error:
            logging.error("Cannot connect to syslog server: %s", server)
            raise

    def send(self, data):
        """
        Sends data to the established connection
        """
        try:
            self.sock.sendall(data.encode())
            logging.info("Syslog feedback sent")
        except socket.timeout:
            logging.error("Connection timeout to syslog server.")
        except socket.error:
            logging.error("Socket error to syslog server")


class GsuiteQuery(object):
    """ Class to hold and structure the gsuite query parameters """

    def __init__(self, app, s_time=None, e_time=None, max="50", user="all"):
        """Initialize the GsuiteQuery class

           Args:
            s_time: Start time for query
            e_time: End time for query
            max:
            user:

        """
        self.app = app
        self.s_time = s_time
        self.e_time = e_time
        self.max = max
        self.user = user
        self.scope = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
        self.secret_file = "client_secret.json"
        self.appname = "Reports API Python Quickstart"
        self.token_file = ".token.pickle"
        self.cred_file = "credentials.json"

    def get_credentials(self):
        """
        Returns user credentials from storage.

        If nothing has been stored, or if the stored credentials are invalid,
        the OAuth2 flow is completed to obtain the new credentials.
        """
        home_dir = os.path.expanduser("~")
        credential_dir = os.path.join(home_dir, ".credentials")
        if not os.path.exists(credential_dir):
            logging.debug("Cred directory not found...creating: %s", credential_dir)
            os.makedirs(credential_dir)
        pickle_path = os.path.join(credential_dir, self.token_file)
        self.creds = None
        if os.path.exists(pickle_path):
            with open(pickle_path, "rb") as token:
                self.creds = pickle.load(token)

        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                try:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.cred_file, self.scope
                    )
                    self.creds = flow.run_console()
                except FileNotFoundError:
                    print(
                        'Google Auth Error: Is the "credentials.json" file in the script directory?\n'
                        "Use the Google Quickstart to generate and download the file at:\n"
                        "https://developers.google.com/admin-sdk/reports/v1/quickstart/python"
                    )
                    sys.exit()

            with open(pickle_path, "wb") as token:
                pickle.dump(self.creds, token)

    def execute(self):
        """
        Returns GSuite events based on given app/activity.
        Other parameters are optional.
        """
        logging.debug("Authenticating to GSuite")
        self.get_credentials()
        service = build("admin", "reports_v1", credentials=self.creds)
        logging.debug(
            "Retrieving %s events from: %s to %s", self.app, self.s_time, self.e_time
        )
        results = (
            service.activities()
            .list(
                userKey=self.user,
                applicationName=self.app,
                startTime=self.s_time,
                endTime=self.e_time,
                maxResults=self.max,
            ).execute()
        )
        return results.get("items", [])


class Bookmark(object):
    """
    Functions to read, write, track update bookmark files
    """

    def __init__(self, activity):
        logging.debug("Init bookmark object: %s.", activity)
        self.bookmark = None
        self.bm_file = "." + activity + ".bookmark"
        bm_data = self._read(self.bm_file)
        if bm_data:
            self.bookmark = dateparser.parse(bm_data)
            logging.debug("Bookmark found: %s", self.bookmark)
        else:
            self.bookmark = datetime.now(timezone.utc) - timedelta(seconds=3600)
        self.new_bookmark = datetime.now(timezone.utc)

    def __repr__(self):
        return self.bookmark.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _read(self, filename):
        """
        Returns RFC 3339 timestamp string from activity bookmark file.
        """
        logging.debug("Looking for bookmark file.")
        try:
            if os.path.getsize(filename) < 10:
                logging.error("Bookmark file appears corrupt: %s", filename)
                return
        except FileNotFoundError:
            logging.debug("Bookmark file not found: %s.", filename)
            return

        try:
            with open(filename, "r") as open_bmfile:
                return open_bmfile.read()
        except OSError:
            logging.debug("Bookmark file cannot be accessed: %s.", filename)
            return

    def update(self, events):
        """
        Stores latest timestamp as bookmark time.

        Validates timestamps for given list of events (record per line as dict).
        """
        for event in events:
            if event.get("id").get("time"):
                event_time = dateparser.parse(event["id"]["time"])
                if event_time > self.bookmark:
                    logging.debug(
                        "Event time newer than Bookmark time: %s > %s",
                        event_time,
                        self.bookmark,
                    )
                    if event_time > self.new_bookmark:
                        logging.debug(
                            "Event time newer than new bookmark time: %s > %s",
                            event_time,
                            self.bookmark,
                        )

                        self.new_bookmark = event_time
                else:
                    logging.debug(
                        "Bookmark time newer then Event time. Bookmark unchanged: %s > %s",
                        self.bookmark,
                        event["id"]["time"],
                    )
            else:
                logging.error("Invalid event time: %s", event["id"]["time"])

    def write(self):
        """
        Writes time to bookmark file. Adds one second to event.
        """

        new_bookmark = self.new_bookmark + timedelta(seconds=1)
        new_bookmark = new_bookmark.strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            with open(self.bm_file, "w") as open_file:
                open_file.write(new_bookmark)
                open_file.flush()
                logging.debug("Updated bookmark file: %s", new_bookmark)
        except OSError:
            logging.error("Bookmark file could not be written")


class Cache(object):
    """
    Functions to create, read, write the event-id cache file
    """

    def __init__(self, activity):
        logging.debug("Building cache for: %s", activity)
        self.activity = activity
        self.cachefile = "." + activity + ".cache"
        self.cache_enabled = True
        self.cache = {}
        self._init_cache

    def _init_cache(self):
        """
        Try to open existing cache file, if no file, call _build_cache
        """
        logging.debug("Looking for cache file: %s", self.cachefile)
        if os.path.exists(self.cachefile) and os.path.getsize(self.cachefile) > 0:
            with open(self.cachefile, "rb") as self.open_cache:
                self.cache = pickle.load(self.open_cache)
                logging.debug("Cache: %s", (self.cache))
        else:
            logging.debug("Cache file not found. Creating from scratch")
            self._build_cache()

    def _build_cache(self):
        """
        Query G Suite to build event_id cache for given activity
        """
        self.gsuite = GsuiteQuery(self.activity, max="50")
        events = self.gsuite.execute()
        if len(events) > 0:
            for cnt, event in enumerate(events, 1):
                self.cache.update({event["id"]["uniqueQualifier"]: event["id"]["time"]})
            logging.debug("Cache built: New event IDs added: %s", cnt)
        else:
            self.cache_enabled = False
            logging.debug("No events found for cache. Caching disabled")

    def dedup_events(self, events):
        """
        Returns time sorted list with any cached events removed.

        Compares given list of events (record per line as a dict) with the cache
        to look for duplicate events.
        """
        logging.debug("Deduplicating events. Processing: %s events.", len(events))
        if not self.cache_enabled:
            logging.error("Caching disabled. No dedup required for %s", self.activity)
            return

        deduped_events = []
        for event in events:
            if event["id"]["uniqueQualifier"] not in self.cache:
                deduped_events.append(event)
                self.cache.update({event["id"]["uniqueQualifier"]: event["id"]["time"]})
            else:
                logging.debug("Duplicate event found in cache:\n %s", event)

        return sorted(deduped_events, key=lambda k: k["id"]["time"])

    def write(self):
        """
        Write cache to file
        """
        logging.debug("Writing bookmark.")
        try:
            with open(self.cachefile, "wb") as open_cache:
                pickle.dump(self.cache, open_cache)
                logging.debug(
                    "Cache file entries written (filename:cnt): %s:%s",
                    self.cachefile,
                    len(self.cachefile),
                )
        except OSError:
            logging.error("Cache file could not be written: %s", self.cachefile)
        else:
            logging.info("Caching disabled. Touching file: %s", self.cachefile)
            touch(self.cachefile)


def touch(touchfile, times=None):
    """
    touch - change file timestamps
    """
    with open(touchfile, "a"):
        os.utime(touchfile, times)


def send_to_syslog(events, syslog):
    """
    Sends iterable event object to syslog socket.
    """
    for cnt, event in enumerate(events, start=1):
        syslog.send(json.dumps(event))
        logging.debug("Event %s sent to syslog: %s.", cnt, json.dumps(event))
    logging.debug("Total Events: %s ", cnt)


def write_events_to_file(events, event_filename):
    """
    Writes list of events to a file.
    """
    try:
        with open(event_filename, "a") as open_eventfile:
            for cnt, event in enumerate(events, start=1):
                json.dump(event, open_eventfile)
                open_eventfile.write("\n")
                logging.debug("Event %s written to file: %s.", cnt, json.dumps(event))
            open_eventfile.flush()
            logging.debug("Wrote events to file: %s", event_filename)
    except OSError:
        logging.error("Event file file could not be written: %s.", event_filename)
    except AttributeError:
        logging.debug("No new events. Event file unchanged")


def main():
    """ Main function """

    syslog_enabled = True

    args = Args(sys.argv)
    pargs = args.get_args()
    logging_init()
    if pargs.level:
        logging.getLogger().setLevel(getattr(logging, pargs.level.upper()))
    logging.debug("******************DEBUG ENABLED******************")
    if pargs.testmode:
        syslog_enabled = False
    configfile = pargs.cfgfile if pargs.cfgfile else "config.ini"

    try:
        event_filename = (
            pargs.event_filename if pargs.event_filename else "gsuite2mfe_events.json"
        )
    except NameError:
        logging.debug("No event file specified.")

    write_eventfile = True if pargs.write_eventfile else False

    try:
        c = Config(configfile, "DEFAULT")
        try:
            syslog_host = c.sysloghost
        except NoOptionError:
            logging.error(
                "syslog_host setting \
                            not detected in: %s.",
                configfile,
            )
            logging.error("Syslog forwarding is disabled.")
            syslog_enabled = False

        try:
            syslog_port = c.syslogport
        except NoOptionError:
            logging.error(
                "syslog_port setting \
                            not detected in: %s.",
                configfile,
            )
            logging.error("Syslog forwarding is disabled.")
            syslog_enabled = False

        try:
            int(syslog_port)
        except ValueError:
            logging.error("Invalid syslog_port: %s", syslog_port)
            logging.error("Syslog forwarding is disabled.")
            syslog_enabled = False

        try:
            activities = c.activities.split(",")
            logging.debug("Log retrieval enabled for: %s", activities)
        except AttributeError:
            activities = ["login"]
            logging.error(
                'activities setting not found in %s. \
                            Using "login" as default.',
                configfile,
            )
    except ValueError:
        logging.error("Config file not found: %s. Entering test mode.", configfile)
        syslog_enabled = False

    use_bookmark = True

    if pargs.s_time:
        s_time = dateparser.parse(pargs.s_time)
        use_bookmark = False

    if pargs.e_time:
        e_time = dateparser.parse(pargs.e_time)
    else:
        e_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    if syslog_enabled:
        try:
            syslog = Syslog(syslog_host, syslog_port)
        except (ValueError, socket.gaierror):
            logging.error("Syslog forwarding disabled.")
            syslog_enabled = False

    for activity in activities:
        logging.debug("*****************")
        logging.debug("Processing actvity: %s", activity)
        logging.debug("*****************")
        if use_bookmark:
            bookmark = Bookmark(activity)
            s_time = str(bookmark)
            cache = Cache(activity)

        gsuite = GsuiteQuery(activity, s_time=s_time, e_time=e_time)
        events = gsuite.execute()

        if not events:
            logging.debug("No events found for activity: %s", activity)
            continue

        if use_bookmark:
            events = cache.dedup_events(events)
            bookmark.update(events)
            bookmark.write()
            cache.write()

        if syslog_enabled:
            send_to_syslog(events, syslog)

        if write_eventfile:
            write_events_to_file(events, event_filename)

        logging.debug("Total events retrieved for %s: %s", activity, len(events))


if __name__ == "__main__":
    try:
        main()
        logging.debug("******************EXECUTE COMPLETE******************")
    except KeyboardInterrupt:
        logging.warning("Control-C Pressed, stopping..")
        sys.exit()
