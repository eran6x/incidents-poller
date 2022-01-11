import sys, getopt
import incidents_poller as ip
import logging
from datetime import datetime

__author__ = 'Eran Amir 2022'

################################
# This script updates incidents 
# Edit the configuration file "restapi.conf" Before running the script 
# the incident_poller is a dependecy
# v 0.1

################################
#   Main Flow 
###############################

def main(argv):

    incident_id = -1
    partition_id = -1
    new_type = ''
    new_action = ''
    new_value = ''


    try:
        opts, args = getopt.getopt(argv,"hi:p:o:t:a:v:",["ifile=","ofile="])
    except getopt.GetoptError:
        print('incident_update.py -i <incident_id> -p <partition_id> -t <INCIDENTS|DISCOVERY> -a <action> -v <value>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('incident_update.py -i <incident_id> -p <partition_id> -t <INCIDENTS|DISCOVERY> -a <action> -v <value>')
            sys.exit()
        elif opt in ("-i"):
            incident_id = int(arg)
        elif opt in ("-p"):
            partition_id = int(arg)
        elif opt in ("-t"):
            new_type = arg
        elif opt in ("-a"):
            new_action = arg
        elif opt in ("-v"):
            new_value = arg

    if (len(argv) == 0 ):
        print('parameters are invalid!')
        sys.exit(1)

    #####################
    #  Global Variables
    #####################
    username  = ''
    password  =  ''
    dlpfsmurl = ''
    accesstoken = ''
    incidents_results_full_path  =  ''  #  Full path to results folder.
    valid_certificate = False
    logged_incident_type = 'INCIDENTS'
    configfile = 'restapi.conf'

    logging.basicConfig(
     filename='DLPAPI.log',
     level=logging.INFO, 
     format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
     datefmt='%H:%M:%S' )
    
    logger = logging.getLogger(__name__)
    #Testing our Logger
    logger.info("DLP update started")

    logger.info("Read Config file")
    username, password, dlpfsmurl,incidents_results_full_path, valid_certificate, logged_incident_type  = ip.read_config(configfile)
    if ( (username) and (password) and (dlpfsmurl) and (incidents_results_full_path)):
        logger.info("Config file ok")
    else :
        logger.error("Bad Config file")
        exit
        
    # get initial token 
    refreshtoken = ip.getrefreshtoken(username,password,dlpfsmurl,valid_certificate)

    # get access token
    accesstoken = ip.getnewaccesstoken(refreshtoken,dlpfsmurl,valid_certificate)
    accesstokenvalid = False
    
############################################################################
#
# update incidents
# 


    responsecode = ip.update_incident(accesstoken,dlpfsmurl, incident_id, partition_id, new_type, new_action, new_value,valid_certificate)
    logger.info('request for {} returned status code: {}'.format(incident_id, responsecode))
    accesstokenvalid = ip.check_validity_at(responsecode)
    # incidents items clount
    # write update to log and to screen. 
    if (not accesstokenvalid): 
        print('request for {} returned status code: {}'.format(incident_id, responsecode))
        logger.error('request for {} returned status code: {}'.format(incident_id, responsecode))


################################
# Main call 
#  Eran Amir 2022(c) 
################################
if __name__ == "__main__":
   main(sys.argv[1:])