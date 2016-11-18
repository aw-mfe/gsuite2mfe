
from apiclient import discovery
from configparser import NoOptionError
from configparser import SafeConfigParser
from datetime import datetime
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

Make sure the permissions on the config.ini file are secure as not to expose any credentials.

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
                description="Send McAfee ESM Alarm data to ServiceNow"
            )
        self.args = args

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

        self.parser.add_argument("fields", nargs='*', metavar='',

                                 help="Key=Values for the query. Example: \n  \
                                 alarm=\"The milk has spilled\" sourceip=\"1.1.1.1\", destip=\"2.2.2.2\" \
                                 The following keys are mapped to fields in SNOW: \
                                 alarm - Description \
                                 sourceip/destip - Node \
                                 severity - Severity")

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
    logger = logging.getLogger('filename')
    fh = logging.FileHandler(logfile, mode='w')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

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
        self.sock.connect((self.server, self.port))

    def send(self, data):
        """
        Sends data to the established connection
        """

        self.data = data
        self.sock.sendall(data.encode())
        logging.info("Syslog feedback sent")


def get_credentials():
    """Gets valid user credentials from storage.

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.

    Returns:
        Credentials, the obtained credential.
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


def main():
    """ Main function """

    args = Args(sys.argv)
    pargs = args.get_args()

    logging_init()

    if pargs.level:
        logging.getLogger().setLevel(getattr(logging, pargs.level.upper()))

    try:
        fields = dict(x.split('=', 1) for x in pargs.fields)
    except ValueError:
        logging.error("Invalid input. Format is field=value")
        sys.exit(1)

    configfile = pargs.cfgfile if pargs.cfgfile else 'config.ini'

    try:
        c = Config(configfile, "DEFAULT")
    except ValueError:
        logging.error("Config file not found: %s", configfile)
        sys.exit(1)

    try:
        syslog_host = c.sysloghost
        syslog_port = c.syslogport
    except NoOptionError:
        logging.debug("Syslog feedback disabled. Settings not detected.")

    bookmarkfile = '.bookmark'

    if os.path.isfile(bookmarkfile):
        logging.debug("Bookmark file detected: %s", bookmarkfile)
        with open(bookmarkfile, 'r') as open_bmfile:
            bookmark = open_bmfile.read()
            logging.debug("File read: %s last timestamp bookmarked", bookmark)

    else:
        bookmark = str(generate(datetime.now(pytz.utc)))
        #bookmark = "2016-11-17T14:53:38.000Z"
        logging.debug("No bookmark file found. Logging events created after %s.", bookmark)
    new_bookmark = str(generate(datetime.now(pytz.utc)))

    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('admin', 'reports_v1', http=http)
    results = service.activities().list(userKey='all', applicationName='login', startTime=bookmark).execute()
    events = results.get('items', [])

    syslog = Syslog(syslog_host, syslog_port)

    for event in events:
        print(json.dumps(event).encode('utf8'))
        syslog.send(json.dumps(event))

    try:
        with open(bookmarkfile, 'w') as open_bmfile:
            open_bmfile.write(new_bookmark)
            open_bmfile.flush()
    except EnvironmentError:
            logging.error("Bookmark file cannot be created!")
            sys.exit(1)
        

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Control-C Pressed, stopping...")
        sys.exit()