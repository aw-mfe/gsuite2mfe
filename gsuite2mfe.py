
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
                                 default=None, dest="s_time", metavar='',
                                 help="Set start time to retrieve events. Format: 2016-11-19T14:53:38.000Z")

        self.parser.add_argument("-e", "--end",
                                 default=None, dest="e_time", metavar='',
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
    filename = (inspect.getfile(inspect.currentframe())
                .split("\\", -1)[-1]).rsplit(".", 1)[0]
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
        if not os.path.isfile(CLIENT_SECRET_FILE):
            logging.error("'client_secret.json file is missing. \
                             Google OAuth must be configured.")
            sys.exit(1)

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
        logging.debug("Missing or invalid time format: %s", timestamp)
        return None

        
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

class Bookmark(object):
    """
    
    """
    def __init__(self, activity):
        logging.debug("Init bookmark object: %s.", activity)
        self.activity = activity
        self.bmfile = "." + activity + '.bookmark'
    
    def read(self):
        """ 
        Returns RFC 3339 timestamp string. Tries to read given file.
        If file cannot be read, current time is returned.
        """
        logging.debug("Looking for bookmark file.")
        try:
            if os.path.getsize(self.bmfile) < 10:
                logging.error("Bookmark file appears corrupt: %s", self.bmfile)
                self.s_time = str(generate(datetime.now(pytz.utc)))
                return self.s_time

        except FileNotFoundError:
            logging.debug("Bookmark file not found: %s.", self.bmfile)
            self.s_time = str(generate(datetime.now(pytz.utc)))
            return self.s_time

        try:
            with open(self.bmfile, 'r') as self.open_bmfile:
                logging.debug("Opening: %s", self.bmfile)
                self.bookmark = self.open_bmfile.read()
                logging.debug("File found. Reading timestamp: %s", 
                                self.bookmark)
                if validate_time('s', self.bookmark):
                    logging.debug("Bookmark time is valid.")
                    self.s_time = self.bookmark
                    return self.s_time
                else:
                    logging.error("Invalid bookmark data. Using current time.")
                    self.s_time = str(generate(datetime.now(pytz.utc)))
                    return self.s_time
        except OSError:
            logging.debug("Bookmark file cannot be accessed: %s.", self.bmfile)
            self.s_time = str(generate(datetime.now(pytz.utc)))
            return self.s_time

    def update(self, events):
        """ 
        Returns latest timestamp as RFC3339 timestamp.
        
        Parameters: s_time: RFC3339 timestamp string
                    events: list of event dicts from Gsuite
        """
        self.events = events
        for self.event in self.events:
            self.evt_time_obj = validate_time('o', self.event['id']['time'])
            if self.evt_time_obj:
                if self.evt_time_obj > validate_time('o', self.bookmark):
                    self.new_bookmark = self.evt_time_obj
                    logging.debug("Event time > Bookmark time: %s", self.event['id']['time'])
                else:
                    logging.debug("Bookmark time > Event time. \
                                   Have latest event time: %s", self.event['id']['time'])
            else: 
                logging.error("Invalid event time. \
                               This should not happen: %s", self.event['id']['time'])

    def write(self):
        """ 
        Writes time to bookmark file. Adds one second to event.
        """

        try:
            self.new_bookmark_p1 = self.new_bookmark + timedelta(0,1)
            self.new_bookmark_str = generate(self.new_bookmark_p1)
            try:
                with open(self.bmfile, 'w') as self.open_bmfile:
                    self.open_bmfile.write(self.new_bookmark_str)
                    self.open_bmfile.flush()
                    logging.debug("Updated bookmark file: %s", self.new_bookmark_str)
            except OSError:
                    logging.error("Bookmark file could not be written.")
        except AttributeError:
            logging.debug("No new timestamps. Bookmark remains unchanged.")

def send_to_syslog(events, syslog):
    """ 
    Sends iterable event object to syslog socket.
    """
    for cnt, event in enumerate(events, start=1):
        syslog.send(json.dumps(event))
        logging.debug("Event %s sent to syslog: %s.", cnt, json.dumps(event))
    logging.debug("Total Events: %s ", cnt)


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

    using_bookmark = True
    s_time = pargs.s_time if validate_time('s', pargs.s_time) else None
    e_time = pargs.e_time if validate_time('s', pargs.e_time) else None
    if s_time or e_time:
        using_bookmark = False
        
    if not testmode:
        syslog = Syslog(syslog_host, syslog_port)
        
    for activity in activities:
        if using_bookmark:
            bookmark = Bookmark(activity)
            s_time = bookmark.read()
            
        if not e_time:
            e_time = str(generate(datetime.now(pytz.utc)))
            logging.debug("End_time set to now: %s", e_time)
    
        events = query_gsuite(activity, s_time, e_time)

        if len(events) > 0:
            if using_bookmark:
                logging.debug("Validating event times.")
                bookmark.update(events)
            if not testmode:
                send_to_syslog(events, syslog)
            else:
                logging.debug(" Total events retrieved from %s: %s", 
                                activity, len(events))
        else:
            logging.debug("No events found for activity: %s.", activity)
        
        if using_bookmark:
            bookmark.write()
        else:
            logging.debug("Bookmark unchanged.")    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Control-C Pressed, stopping...")
        sys.exit()
