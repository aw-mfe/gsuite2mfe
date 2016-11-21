
from apiclient import discovery
from configparser import NoOptionError
from configparser import SafeConfigParser
from datetime import datetime
from datetime import timedelta
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage
from pyrfc3339 import parse
from pyrfc3339 import generate

import argparse
import base64
import httplib2
import inspect
import ipaddress
import json
import logging
import logging.config
import os
import pytz
import socket
import sys
import time

SCOPES = 'https://www.googleapis.com/auth/admin.reports.audit.readonly'
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'Reports API Python Quickstart'


""" G Suite/Google Apps Events -> McAfee ESM

This will pull events from G Suite (formerly Google Apps) and forward the
events to a McAfee ESM.

The script requires Python 3 and was tested with 3.5.2 for Windows and Linux.

The module requirements list is quite extensive. Please see the requirements file.

The script requires a config.ini file for the Receiver IP and port. An alternate
config file can be specified from the command line.

An example config.ini is available at:
https://raw.githubusercontent.com/andywalden/gsuite2ESM/config.ini

This is intended to be called as a cron task. A bookmark file is created in the
same directory. If the bookmark file does not exist, one will be created and
future events will be forwarded.

Make sure the permissions on the config.ini file are secure as not to expose 
any credentials.

"""

__author__ = "Andy Walden"
__version__ = ".1"

class Args(object):
    """
    Handles any args and passes them back as a dict
    """

    def __init__(self, args):
        self.log_levels = ["quiet", "error", "warning", "info", "debug"]
        self.formatter_class = argparse.RawDescriptionHelpFormatter
        self.parser = argparse.ArgumentParser(
                formatter_class=self.formatter_class,
                description="Send Google GSuite events to McAfee ESM"
            )
        self.args = args

        self.parser.add_argument("-s", "--start",
                                 default=None, dest="starttime", metavar='',
                                 help="Set start time to retrieve events. Format: 2016-11-19T14:53:38.000Z")

        self.parser.add_argument("-e", "--end",
                                 default=None, dest="endtime", metavar='',
                                 help="Set end time to retrieve events. Format: 2016-11-19T14:53:38.000Z")

        self.parser.add_argument("-t", "--test",
                                 action='store_true',
                                 dest="testmode",
                                 help="Disable syslog forwarding. Combine with -l debug for console output.")
        self.parser.set_defaults(testmode = False)

        self.parser.add_argument("-v", "--version",
                                 action="version",
                                 help="Show version",
                                 version="%(prog)s {}".format(__version__))

        self.parser.add_argument("-l", "--level",
                                 default=None, dest="level",
                                 choices=self.log_levels, metavar='',
                                 help="Logging output level. Default: warning")

        self.parser.add_argument("-c", "--config",
                                 default=None, dest="cfgfile", metavar='',
                                 help="Path to config file. Default: config.ini")

        self.parser.add_argument("-b", "--bookmark",
                                 default=None, dest="bookmarkfile", metavar='',
                                 help="Path to bookmark file. Default: .bookmark")

        self.pargs = self.parser.parse_args()

    def get_args(self):
        return self.pargs


class Config(object):
    """ Creates object for provided configfile/section settings """

    def __init__(self, filename, header):
        config = SafeConfigParser()
        cfgfile = config.read(filename)
        if not cfgfile:
            raise ValueError('Config file not found:', filename)
        self.__dict__.update(config.items(header))


def logging_init():
    filename = get_filename()
    logfile = filename + ".log"
    hostname = socket.gethostname()
    formatter = logging.Formatter('%(asctime)s {} %(module)s: %(message)s'.format(hostname),
                                    datefmt='%b %d %H:%M:%S')
    logger = logging.getLogger()
    fh = logging.FileHandler(logfile, mode='w')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logging.getLogger('googleapiclient').setLevel(logging.CRITICAL)

def get_filename():
    filename = (inspect.getfile(inspect.currentframe()).split("\\", -1)[-1]).rsplit(".", 1)[0]
    return filename


class Syslog(object):
    """
    Open TCP socket using supplied server IP and port.
    
    Returns socket or None on failure
    """

    def __init__(self,
                server,
                port=514):
        logging.debug("Function: open_socket: %s: %s", server, port)
        self.server = server
        self.port = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.connect((self.server, self.port))
        except socket.timeout:
            logging.error("Connection timeout to syslog: %s", self.server)
        except socket.error:
            logging.error("Socket error to syslog: %s", self.server)
            
    def send(self, data):
        """
        Sends data to the established connection
        """
        self.data = data
        try:
            self.sock.sendall(data.encode())
            logging.info("Syslog feedback sent")
        except socket.timeout:
            logging.error("Connection timeout to syslog: %s", self.server)
        except socket.error:
            logging.error("Socket error to syslog: %s", self.server)


def get_credentials():
    """
    Returns valid user credentials from storage.

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.
    """
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir,
                                   'admin-reports_v1-python-quickstart.json')

    store = Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
    return credentials

    
def validate_time(return_type, timestamp):
    """If the timestamp is valid a RFC 3339 formatted timestamp, a string
    or object will be returned based upon the return_type of either 's', or 'o'
    """
    try:
        logging.debug("Validating timestamp: %s", timestamp)
        time_obj = parse(timestamp)
        if return_type == 'o':
            return time_obj
        else:
            return timestamp
    except (ValueError, TypeError):
        logging.error("Missing or invalid time format: %s", timestamp)
        return None

        
def add_time(seconds, timestamp):
    """
    Returns an RFC 3339 formatted string with the given number of seconds added.
    """
    return parse(timestamp) + timedelta(seconds)


def query_gsuite(app, s_time, e_time):
    """ 
    Returns GSuite events based on given app.
    Start time and End time are optional parameters.
    """
    logging.debug("Authenticating to GSuite.")
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('admin', 'reports_v1', http=http)
    logging.debug("Retrieving %s events from: %s to %s", app, s_time, e_time)
    results = service.activities().list(userKey='all', 
                                        applicationName=app, 
                                        startTime=s_time,
                                        endTime=e_time).execute()
    return results.get('items', [])


def get_latest_time(s_time, **events):
    """ 
    Returns latest timestamp as RFC3339 timestamp.
    
    Parameters: s_time: RFC3339 timestamp string
                events: list of event dicts from Gsuite
    """
    for event in events:
        evt_time_obj = validate_time('o', event['id']['time'])
        if evt_time_obj:
            if evt_time_obj > validate_time('o', s_time):
                logging.debug("Event time > Bookmark time: %s", event['id']['time'])
                return validate_time('s', event['id']['time'])
            else:
                logging.debug("Bookmark time > Event time. \
                               Have latest event time: %s", event['id']['time'])
                return s_time
        else: 
            logging.error("Invalid event time. \
                           This should not happen: %s", event['id']['time'])
            return s_time
    
def send_to_syslog(events, syslog):
    """ 
    Sends iterable event object to syslog socket.
    """
    for cnt, event in enumerate(events, start=1):
        syslog.send(json.dumps(event))
        logging.debug("Event %s sent to syslog: %s.", cnt, json.dumps(event))
    logging.debug("Total Events: %s ", cnt)

    
def update_bookmark(s_time, bmfile):
    """ 
    Writes time to bmfile.
    """
    try:
        with open(bookmarkfile, 'w') as open_bmfile:
            # Add one second to the bookmark time to move past last event seen
            open_bmfile.write(s_time)
            open_bmfile.flush()
            logging.debug("Updated bookmark file: %s", s_time)
    except OSError:
            logging.error("Bookmark file could not be written.")

            
def read_bookmark(bookmarkfile):
    """ 
    Returns RFC 3339 timestamp string if found in provided file
    """
    logging.debug("Looking for bookmark file.")
    try:
        with open(bookmarkfile, 'r') as open_bmfile:
            bookmark = open_bmfile.read()
            logging.debug("File found. Reading timestamp: %s", bookmark)
            if validate_time('s', bookmark):
                s_time = bookmark
                logging.debug("Bookmark time is valid.")
            else:
                logging.debug("Bookfile file found data not as expected. \
                               Creating new bookmark starting now.")
                s_time = str(generate(datetime.now(pytz.utc)))
        return s_time
    except OSError:
        s_time = str(generate(datetime.now(pytz.utc)))
        logging.debug("No bookmark file found. Events created \
                       after %s will be forwarded.", s_time)
        return s_time


def main():
    """ Main function """

    args = Args(sys.argv)
    pargs = args.get_args()
    logging_init()

    if pargs.level:
        logging.getLogger().setLevel(getattr(logging, pargs.level.upper()))
    
    testmode = pargs.testmode
    configfile = pargs.cfgfile if pargs.cfgfile else 'config.ini'

    try:
        c = Config(configfile, "DEFAULT")
        try:
            syslog_host = c.sysloghost
            syslog_port = c.syslogport
        except NoOptionError:
            logging.debug("'syslog_host' or 'syslog_port' setting \
                            not detected in: %s.", configfile)
            logging.debug("Enabling testmode.")
            testmode = True
        try:
            activities = c.activities.split(',')
            logging.debug("Log retrieval enabled for: %s", activities)
        except AttributeError:
            activities = ['login']
            logging.error("'activities' setting not found in %s. \
                            Using 'login' as default.", configfile)
    except ValueError:
        logging.error("Config file not found: %s. Entering test mode.", configfile)
        testmode = True
        # Enabling login events for barebones testmode
        activities = ['login']
        
    using_bookmark = False
    time_stor = {}    
    time_stor['startTime'] = pargs.starttime if validate_time('s', pargs.starttime) else None
    time_stor['endTime'] = pargs.endtime if validate_time('s', pargs.endtime) else None
    s_time = time_stor['startTime']
    e_time = time_stor['endTime']
    bookmarkfile = pargs.bookmarkfile if pargs.bookmarkfile else '.bookmark'
    
    if not s_time:
        s_time = read_bookmark(bookmarkfile)
        bookmark = s_time
        using_bookmark = True
    if not e_time:
        e_time = str(generate(datetime.now(pytz.utc)))
        logging.debug("Querying with end_time set to now: %s", e_time)
        
    if not testmode:
        syslog = Syslog(syslog_host, syslog_port)

    for activity in activities:
        events = query_gsuite(activity, s_time, e_time)
        if len(events) > 0:
            bookmark = get_latest_time(events)
            if not testmode:
                send_to_syslog(events, syslog)
            else:
                logging.debug(" Total events retrieved from %s: %s", 
                                activity, len(events))
        else:
            logging.debug("No events found for %s.", activity)

    if using_bookmark and bookmark is not s_time:
        new_bookmark = add_time(1, s_time)
        update_bookmark(new_bookmark, bookmarkfile)
    else:
        logging.debug("No new events. Bookmark unchanged.")    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Control-C Pressed, stopping...")
        sys.exit()
