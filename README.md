# incidents-poller
Introduction:
=============
A connector app to poll incidents from Forcepoint DLP FSM using RestAPI
Update incident script can be integrated into SOAR.

Prequisites: 
============
This script works with python 3.x

Description: 
============
script:
incident poller: retrieve new incidents from NOW in 5m intervals.
usage:
python incidents_poller.py

script:
incident update: update incident deails: 
usage:
python incident_update.py  -i 1734266 -p 20211011 -t INCIDENTS -a STATUS -v CLOSED

Troubleshooting:
================

for new python installations, you might need to run a few commands to import the packages: (run commands in command line)

pip install sys
pip install getopt
pip install requests

for:
import sys
import getopt
import requests

