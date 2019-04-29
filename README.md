# gsuite2mfe
Send events from G Suite to McAfee SIEM

This will pull events from G Suite (formerly Google Apps) and forward the events to a McAfee ESM. The script uses the Google Apps Activity API: https://developers.google.com/google-apps/activity/.

## Overview

The script requires Python 3 and was tested with 3.5.2 for Windows and Linux. You will want to use virtualenv or Anaconda to create a runtime environment. 

This is intended to be called as a cron or Task Manager task. If it can find a bookmark file, it will query from the time listed. If not, it will create a bookmark file with the current time and send any future events.

## Installation
One method of installation using virtualenv is:

    $ git clone https://github.com/andywalden/gsuite2mfe
    $ virtualenv -p /usr/bin/python3 gsuite2mfe
    $ cd gsuite2mfe
    $ source bin/activate
    $ pip install -r requirements.txt

Copy/Paste Friendly:

    git clone https://github.com/andywalden/gsuite2mfe
    virtualenv -p /usr/bin/python3.5 gsuite2mfe
    cd gsuite2mfe
    source bin/activate
    pip install -r requirements.txt


## Local Configuration
Edit the config.ini to set the IP address the events will be forwarded and enable/disable retrieval of log types or 'activities'. 

The activities line is a comma delimited (no spaces) list of event types, or 'activities' to query for. Currently GSuite supports: 

admin,calendar,drive,login,mobile,token,groups,saml,chat,gplus,rules,jamboard,meet,user_accounts,access_transparency,groups_enterprise

Per: https://developers.google.com/admin-sdk/reports/v1/reference/activities/list

Remove an activity from the list to disable event collection for that activity.

## Enable GSuite Authentication

Before the script can be used, install the API credentials. [Google has a Python quick start process to get things set up](https://developers.google.com/admin-sdk/reports/v1/quickstart/python). 

In summary, as they are listed on the Quick Start page:
 1. Step 1 - click the button to enable the Reports API.
 2. You will be prompted to log in to your GSuite account if you are not already.
 3. A pop-up will appear with the Client ID and Client Secret. Click the button at the top to download the Client Configuration. Leave the file named credentials.json and save it to the same directory as the gsuite2mfe script.
 4. Run the script. If you're on a desktop, your browser should open to prompt for authorization. If you're at a console, an authorization URL will be generated for copy/pasting into a browser. 
 5. Once the script is authorized the token will be saved in the accounts home directory in a subdirectory called .credentials which should be protected. 


As an alternative to the Quick Start, the steps below are a bit more manual but are tested and known working.

1. Go to the [Google API Manager](https://console.developers.google.com/iam-admin/projects).
2. Create a new project called 'gsuite2mfe'. It might take a few minutes but then will refresh to the API Library.
3. Enter 'Admin SDK' into the search box and select the link.
4. Click the Enable button at the top of the screen.
5. Click Credentials on the left menu bar.
6. Click Create Credentials then OAuth client ID.
4. Click the Configure consent screen button.
5. Enter 'gsuite2mfe' as the Product name shown to users. Click Save.
6. Select Other as the Application type and enter 'gsuite2mfe' as the Name. Click Create.
7. You will be shown the client ID and client secret. Click OK.
8. The credentials will be listed under OAuth 2.0 client IDs. Click the Download button at the far right to download the json file. Save it as client_secret.json and put it into the script directory.
9. Run the command: python quickstart.py --noauth_local_webserver
10. Paste the link into your browser, click Allow and copy the supplied code.
11. Paste the code back into the terminal with the script.
12. The script will return the last 10 logins to show that it is working.


## Setting Up Interval Polling

Since the script is running in a virtual environment, it's helpful to have a shell script to set things up. 

gsuite2mfe.sh needs to be edited to include the correct path to the script.

    #!/bin/bash
    cd /home/user/gsuite2mfe  <--
    source bin/activate
    python gsuite2mfe.py


Then set the script to run at an interval. To have cron query every minute, do the following:

    $ crontab -e

At the bottom of the file, insert this line (replace the path with actual path):

    * * * * * /home/user/gsuite2mfe/gsuite2mfe.sh

## Installing the ruleset

There are custom parsing rules to parse the events in 'rules.xml'. I haven't had a chance to see all of the events so there might be some updates here. I also had to make some choices in regards to the fields that were parsed in some of the events but everything can be easily customized using the Rules Editor.

To import the rules:

1. Create a GSuite datasource with:
    - Data Source type set to: Generic Syslog
    - IP address of the device this script is running on
    - Time zone set to: GMT
2. Select the data source in the Device tree on the left and click the Edit Policy icon above the Device Tree.
3. The Policy Manager will, open, select Advanced Syslog Parser on the left.
4. On the top menu, click File and Import.
5. Choose the rules.xml file included with the script and click Import.
6. Enable the rules under the GSuite datasource, Save and Rollout the policy.

## Extras
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
