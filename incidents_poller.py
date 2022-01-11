import json
import time
import logging
import requests
from datetime import datetime
import pprint

__author__ = 'Eran Amir 2022'

################################
# This script retrives incidents from launch time onwards in continuous loop.
# Edit the configuration file "restapi.conf" Before running the script 
# v 0.2

################################
# Read config From file
#
################################
def read_config(configfile):
    file1 = open(configfile, 'r')
    Lines = file1.readlines()

    for line in Lines:
        if ( line.startswith('#') or line.startswith('\n') ) :
            continue
        line0 = line.split('=')[0]
        line1 = (line.split('=')[1])
        line1 = line1. rstrip("\n")

        if line0.lower() in ['hostname', 'Hostname']:
            dlpfsmurl = line1
        elif line0.lower() in ['username', 'Username']:
            username = line1
        elif line0.lower() in ['password', 'Password']:
            password = line1
        elif line0.lower() in ['location', 'Location']:
            incidents_results_full_path = line1
        elif line0.lower() in ['incident_type']:
            logged_incident_type = line1 #must be INCIDENTS or DISCOVERY
        elif line0.lower() in ['verifycert', 'Verifycert']:
            valid_certificate = True if (line1.lower() == 'true') else False
        else:
            pass
    return username, password, dlpfsmurl, incidents_results_full_path, valid_certificate,logged_incident_type

################################
# Get a <Refresh Token> from 
#  credentials.
################################
def getrefreshtoken(username,password,dlpfsmurl,valid_certificate):
    headerz = {"username" : username, "password" : password}
    urlz = 'https://{}/dlp/rest/v1/auth/refresh-token'.format(dlpfsmurl)
    r={}
    try:
        r = requests.post(urlz,headers=headerz,verify=valid_certificate)
        response = json.loads(r.text)
        print('Refresh token={}'.format((response["refresh_token"])[-10:]))
    except Exception as err:
        print (err)
 
    if r.status_code == 200:
        return response["refresh_token"]
    else:
        return None      
  
################################
# Get <Access Token> from Refresh 
#  token.
################################
def getnewaccesstoken(refreshtoken,dlpfsmurl,valid_certificate):
    #data = {}
    headerz = {"refresh-token" : "Bearer {}".format(refreshtoken) }
    urlz = 'https://{}/dlp/rest/v1/auth/access-token'.format(dlpfsmurl)
    r={}
    try:
        r = requests.post(urlz,headers=headerz,verify=valid_certificate)
        response = json.loads(r.text)
        print('New Access token={}'.format((response["access_token"])[-10:]))
    except Exception as err:
        print (err)
        exit
 
    if r.status_code == 200:
        return response["access_token"]
    else:
        return None   
  
################################
# Get incidents by access 
#  token and ranges
################################   
def retrieve_incidents(accesstoken,dlpfsmurl):
    
    data = {}
    responsecode = 200
    headerz = {"Authorization" : "Bearer {}".format(accesstoken) , "Content-Type": "application/json"}
    urlz = 'https://{}/dlp/rest/v1/incidents'.format(dlpfsmurl)
    ##TBD make dynamic incidents with range taken from file.
    data = '{ "sort_by" : "INSERT_DATE", "type" : "INCIDENTS", "from_date" : "01/01/2022 00:00:00", "to_date" : "04/01/2022 23:59:59" }' 
    r={}
    try:     
        r = requests.post(urlz, headers=headerz, data=data, verify=False)
        response = json.loads(r.text)
        if r.ok : 
            responsecode = 200
        else :
            responsecode = r.status_code

        return response, responsecode
    except Exception as err:
        print (err)
        exit

######################################
# retrieve incidents by time frame
def retrieve_incidents_for_tf(accesstoken,dlpfsmurl, start_tf, end_tf,valid_certificate,logged_incident_type):
    response = {}
    responsecode = 200
    headerz = {"Authorization" : "Bearer {}".format(accesstoken) , "Content-Type": "application/json"}
    urlz = 'https://{}/dlp/rest/v1/incidents'.format(dlpfsmurl)
    data_dict = { "sort_by" : "INSERT_DATE" }
    data_dict["type"] = logged_incident_type
    data_dict["from_date"] = start_tf
    data_dict["to_date"] =  end_tf
    sdata=json.dumps(data_dict)
    r={}
    try:
        r = requests.post(urlz, headers=headerz, data=sdata, verify=valid_certificate)
    except Exception as err:
        print (err)
        exit

    if r.ok : 
        response = json.loads(r.text)
    else :
        print(r.reason)
        responsecode = r.status_code
    return response, responsecode

######################################
# retrieve incidents by time frame
# example data: 
# '{ 
#     "incident_keys" : [ { "incident_id" : 271966800000, "partition_index": 20210831 } ],   
#     "type" : "INCIDENTS", 
#     "action_type" : "STATUS", 
#     "value" : "NEW"  
# }'
def update_incident(accesstoken,dlpfsmurl, incident_id, partition_id, new_type, new_action, new_value,valid_certificate):

    headerz = {"Authorization" : "Bearer {}".format(accesstoken) , "Content-Type": "application/json"}
    urlz = 'https://{}/dlp/rest/v1/incidents/update'.format(dlpfsmurl)

    ii_dict = {}
    ii_dict["incident_id"] =  incident_id
    ii_dict["partition_index"] = partition_id 

    ip_array = []
    ip_array.append(ii_dict)

    data_dict = {}
    data_dict["incident_keys"] =  ip_array
    data_dict["type"] =  new_type
    data_dict["action_type"] = new_action 
    data_dict["value"] =   new_value

    sdata=json.dumps(data_dict)
    r={}
    try:
        r = requests.post(urlz, headers=headerz, data=sdata, verify=valid_certificate)
    except Exception as err:
        print (err)
        exit

    return r.status_code




################################
# #TBD chck the access token from the previous response
# return True/False
def check_validity_at(response):
    if response == 200:
        return True
    else:
        return False
 

################################
# Write incidents as files  
#  in results folder
################################
def writetofile(incidents_bulk,incidents_results_full_path):
    now = datetime.now() # current date and time
    date_time = now.strftime("_%m-%d-%Y-%H-%M-%S")

    ## TBD:  add path for windows or linux with if statement selection 
    filename = incidents_results_full_path + '/DLP_incidnets' + date_time + '.log'
    incident_list = incidents_bulk.get('incidents')

    file=open(filename, mode="wt", encoding='utf-8')
    for items in incident_list:
        output_s = pprint.pformat(items) 
        output_s = output_s.replace("\n", " ")
        output_s += '\n'      
        file.write(output_s)
    file.close()
    return str('completed writing {} incidents to {}'.format(len(incident_list),filename))

def get_time_frame_for_next_request(timestamp, seconds):
    dt = datetime.now()
    ts2 = datetime.timestamp(dt)
    ts1 = ts2 - seconds

    end_tfx = datetime.fromtimestamp(ts2)
    start_tfx = datetime.fromtimestamp(ts1)

    # convert timestamp to string in dd-mm-yyyy HH:MM:SS
    start_tf = start_tfx.strftime("%d/%m/%Y %H:%M:%S")
    end_tf = end_tfx.strftime("%d/%m/%Y %H:%M:%S")

    return start_tf, end_tf 


################################
#   Main Flow 
###############################

def main():
        
    #####################
    #  Global Variables
    #####################
    username  = ''
    password  =  ''
    dlpfsmurl = ''
    accesstoken = ''
    incidents_results_full_path  =  ''  #  Full path to results folder.
# TBD add these variables to the functions:
    valid_certificate = False
    logged_incident_type = 'INCIDENTS'
    configfile = 'restapi.conf'
    polling_interval = 5 * 60 # seconds
    
    logging.basicConfig(
     filename='DLPAPI.log',
     level=logging.INFO, 
     format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
     datefmt='%H:%M:%S' )
    
    logger = logging.getLogger(__name__)
    #Testing our Logger
    logger.info("DLP RestAPI started")

    logger.info("Read Config file")
    username, password, dlpfsmurl,incidents_results_full_path, valid_certificate, logged_incident_type  = read_config(configfile)
    if ( (username) and (password) and (dlpfsmurl) and (incidents_results_full_path)):
        logger.info("Config file ok")
    else :
        logger.error("Bad Config file")
        exit
        
    # get initial token 
    refreshtoken = getrefreshtoken(username,password,dlpfsmurl,valid_certificate)

    # get access token
    accesstoken = getnewaccesstoken(refreshtoken,dlpfsmurl,valid_certificate)
    accesstokenvalid = False
    
############################################################################
#
# This part is an endless loop where we try to retrieve the next incidents
# 
    while (True):
        if (accesstokenvalid):
            start_tf, end_tf = get_time_frame_for_next_request(datetime.timestamp, polling_interval ) #5 min

            incidents_bulk, responsecode = retrieve_incidents_for_tf(accesstoken,dlpfsmurl, start_tf, end_tf,valid_certificate, logged_incident_type)
            logger.info('request for {} returned status code: {}'.format(logged_incident_type, responsecode))
            accesstokenvalid = check_validity_at(responsecode)
            # incidents items clount
            if (accesstokenvalid and incidents_bulk['total_count'] > 0): 
                status =writetofile(incidents_bulk,incidents_results_full_path)
                logger.info(status)
        else:
            accesstoken = getnewaccesstoken(refreshtoken,dlpfsmurl,valid_certificate)
            if (accesstoken) : accesstokenvalid = True

        # TBD calculate the next interation before continueing to retrive.
        now = datetime.now() # current date and time
        logger.info('sleep time: {}'.format(now.strftime("_%m-%d-%Y-%H-%M-%S")) )
        time.sleep(polling_interval) #wait until next iteration

# the previous iteration that retrieves the old incidents.
    while (True):
        if (accesstokenvalid):
            incidents_bulk, responsecode = retrieve_incidents(accesstoken,dlpfsmurl)
            accesstokenvalid = check_validity_at(responsecode)
            # incidents items clount
            if (incidents_bulk['total_count'] > 0): 
                writetofile(incidents_bulk,incidents_results_full_path)
        else:
            accesstoken = getnewaccesstoken(refreshtoken,dlpfsmurl)
            if (accesstoken) : accesstokenvalid = True

        # TBD calculate the next interation before continueing to retrive.
         
        time.sleep(polling_interval) #wait one mintue until next iteration

#TBD retrive discovery incidents

################################
# Main call 
#  Eran Amir 2021 (c) 
################################
if __name__ == "__main__":
    main()
