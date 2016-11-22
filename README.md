# gsuite2mfe
Send events from G Suite to McAfee SIEM

This will pull events from G Suite (formerly Google Apps) and forward the events to a McAfee ESM. The script uses the Google Apps Activity API: https://developers.google.com/google-apps/activity/.

## Overview

The script requires Python 3 and was tested with 3.5.2 for Windows and Linux. You will want to use virtualenv or Anaconda to create a runtime environment. 

This is intended to be called as a cron or Task Manager task. If it can find a bookmark file, it will query from the time listed. If not, it will create a bookmark file with the current time and send any future events.

## Installation
One method of installation using virtualenv is:

    user@lnxbx:~$ git clone https://github.com/andywalden/gsuite2mfe
    user@lnxbx:~$ virtualenv -p /usr/bin/python3.5 gsuite2mfe
    user@lnxbx:~$ cd gsuite2mfe
    user@lnxbx:~$ source bin/activate
    user@lnxbx:~$ pip install -r requirements.txt

## Local Configuration
Edit the config.ini to set the IP address the events will be forwarded and enable/disable retrieval of log types or 'activities'. 

The activities line is a comma delimited (no spaces) list of event types, or 'activities' to query for. Currently GSuite supports: 

admin,calendar,drive,groups,login,mobile,token

Per: https://developers.google.com/admin-sdk/reports/v1/reference/activities/list

Remove an activity from the list to disable event collection for that activity.

## Enable GSuite Authentication

Before the script can be used, install the API credentials. [Google has a great Python quick start process to get things set up](https://developers.google.com/admin-sdk/reports/v1/quickstart/python). It is summarized below.


1. Go to the [Wizard to enable the API](https://console.developers.google.com/flows/enableapi?apiid=admin).
2. Create a new project called gsuite2mfe.
3. Click Create Credentials then OAuth client ID.
4. Click the Configure consent screen button
5. Enter gsuite2mfe as the Product name shown to users. Click Save.
6. Select Other as the Application type and enter "Reports API Quickstart" as the Name. Click Create.
7. You will be shown the client ID and client secret. Click OK.
8. The credentials will be listed under OAuth 2.0 client IDs. Click the Download button at the far right to download the json file. Save it as client_secret.json and put it into the script directory.
9. Run python quickstart.py and follow the process to enable authentication.


## Setting Up Interval Polling

Since the script is running in a virtual environment, it's helpful to have a shell script to set things up. 

gsuite2mfe.sh needs to be edited to include the correct path to the script.

Then set the script to run at an interval. To have cron query every minute, do the following:

    user@lnxbx:~$ crontab -e

At the bottom of the file, insert this line (replace the path with actual path):

    * * * * * /home/user/gsuite2mfe/gsuite2mfe.sh

The script also supports some options:

usage: gsuite2mfe.py [-h] [-s] [-e] [-t] [-v] [-l] [-c]

Send Google GSuite events to McAfee ESM

    optional arguments:
    -h, --help      show this help message and exit
    -s , --start    Set start time to retrieve events. Format:
                      2016-11-19T14:53:38.000Z
    -e , --end      Set end time to retrieve events. Format:
                      2016-11-19T14:53:38.000Z
    -t, --test      Disable syslog forwarding. Combine with -l debug for console
                      output.
    -v, --version   Show version
    -l , --level    Logging output level. Default: warning
    -c , --config   Path to config file. Default: config.ini

In addition to operating at interval and keeping state with bookmarks, the script can also be run in a "one off" mode. 

The most common option is -s to indicate when to start retrieving events from. If no end time is specified, the current time is used. 

It is likely that -s would want to be combined with -t which will prevent the events queried from being forwarded to syslog. This allows for events to be manually extracted without sending duplicates to the syslog destination.

Otherwise, '-l debug' creates a fairly verbose story about what is going on as the script runs. 

Please send any bug reports or suggestions to gsuite2mfe at krakencodes dot com.
