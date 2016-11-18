# gsuite2mfe
Send events from G Suite to McAfee SIEM


This will pull events from G Suite (formerly Google Apps) and forward the events to a McAfee ESM.

The script requires Python 3 and was tested with 3.5.2 for Windows and Linux. You will want to use virtualenv or Anaconda to create a runtime environment. 

This is intended to be called as a cron or Task Manager task. If it can find a bookmark file, it will query from the time listed. If not, it will create a bookmark file with the current time and send any future events.

One method of installation using virtualenv is:

    user@lnxbx:~$ virtualenv -p /usr/bin/python3.5 gsuite2mfe
    user@lnxbx:~$ cd gsuite2mfe
    user@lnxbx:~$ git clone https://github.com/andywalden/gsuite2mfe
    user@lnxbx:~$ pip install -r requirements.txt
    user@lnxbx:~$ crontab -e

At the bottom of the file, insert this line:
    * * * * * /home/user/gsuite2mfe/gsuite2mfe.sh


The script requires a config.ini file for the Receiver IP and port. An alternate config filename can be specified from the command line.

An example config.ini is available at:
https://raw.githubusercontent.com/andywalden/gsuite2mfe/config.ini


Make sure the permissions on the config.ini file are secure as not to expose any credentials.
