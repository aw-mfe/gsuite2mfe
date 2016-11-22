
from __future__ import print_function
import httplib2
import os

from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage

try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

# If modifying these scopes, delete your previously saved credentials
# at ~/.credentials/admin-reports_v1-python-quickstart.json
SCOPES = 'https://www.googleapis.com/auth/admin.reports.audit.readonly'
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'Reports API Python Quickstart'


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
        if flags:
            credentials = tools.run_flow(flow, store, flags)
        else: # Needed only for compatibility with Python 2.6
            credentials = tools.run(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials

def main():
    """Shows basic usage of the Google Admin SDK Reports API.

    Creates a Google Admin SDK Reports API service object and outputs a list of
    last 10 login events.
    """
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('admin', 'reports_v1', http=http)

    print('Getting the last 10 login events')
    results = service.activities().list(userKey='all', applicationName='login',
        maxResults=10).execute()
    activities = results.get('items', [])

    if not activities:
        print('No logins found.')
    else:
        print('Logins:')
        for activity in activities:
            print('{0}: {1} ({2})'.format(activity['id']['time'],
                activity['actor']['email'], activity['events'][0]['name']))


if __name__ == '__main__':
    main()
