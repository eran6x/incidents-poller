####################################
#
# Filter on:   Policy =  "USB action"
#              Status = "New"
# "status" : "NEW"
# "policies" : "PCI"
# "channel" : "ENDPOINT_REMOVABLE_MEDIA",

###################################
import json
import logging
import pprint
from datetime import datetime
import sys
import requests
import servicenow_incident

__author__ = 'Eran Amir 2022'

################################
# This script retrives incidents from launch time onwards in continuous loop.
# Edit the configuration file "restapi.conf" Before running the script
# v 0.3

################################
# Read config From file
#
################################
def read_config(configfile):
    ''' Read connection info and configuration from restapi.conf file'''
    file1 = open(configfile, 'r', encoding="utf8")
    lines = file1.readlines()

    for line in lines:
        if ( line.startswith('#') or line.startswith('\n') ) :
            continue
        line0 = line.split('=')[0]
        line1 = (line.split('=')[1])
        line1 = line1. rstrip("\n")
        # TODO remove the second option with uppercase
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
        elif line0.lower() in ['servicenow_enabled', 'Servicenow_enabled']:
            servicenow_enabled = True if (line1.lower() == 'true') else False
        elif line0.lower() in ['servicenow_instance', 'Servicenow_instance']:
            servicenow_instance = line1
        elif line0.lower() in ['servicenow_user', 'Servicenow_user']:
            servicenow_user = line1
        elif line0.lower() in ['servicenow_password', 'Servicenow_password']:
            servicenow_password = line1
        elif line0.lower() in ['servicenow_create_incident_from']:
            servicenow_create_incident_from = line1

        else:
            pass
    return username, password, dlpfsmurl, incidents_results_full_path,valid_certificate, \
           logged_incident_type, servicenow_enabled, servicenow_instance, servicenow_user, \
           servicenow_password, servicenow_create_incident_from

################################
# Get a <Refresh Token> from
#  credentials.
################################
def getrefreshtoken(username,password,dlpfsmurl,valid_certificate):
    '''Get a <Refresh Token> from credentials.'''
    headerz = {"username" : username, "password" : password}
    urlz = 'https://{}/dlp/rest/v1/auth/refresh-token'.format(dlpfsmurl)
    r={}
    try:
        r = requests.post(urlz,headers=headerz,verify=valid_certificate)
        response = json.loads(r.text)
        print('Refresh token={}..xxxx'.format((response["refresh_token"])[-10:]))
    except requests.exceptions.RequestException as err:
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
    '''Get <Access Token> from Refresh token.'''
    #data = {}
    #headerz = {"refresh-token" : "Bearer {}".format(refreshtoken) }
    headerz = {"refresh-token" : f"Bearer {refreshtoken}" }
    #urlz = 'https://{}/dlp/rest/v1/auth/access-token'.format(dlpfsmurl)
    urlz = f'https://{dlpfsmurl}/dlp/rest/v1/auth/access-token'
    request={}
    try:
        request = requests.post(urlz,headers=headerz,verify=valid_certificate)
        response = json.loads(request.text)
#        print('New Access token={}..xxxx'.format((response["access_token"])[-10:]))
        print(f'New Access token={(response["access_token"])[-10:]}..xxxx')
    except requests.exceptions.RequestException as err:
        print (err)
        sys.exit()

    if request.status_code == 200:
        return response["access_token"]
    return None

################################
# Get incidents by access 
#  token and ranges
################################   
def retrieve_incidents(accesstoken,dlpfsmurl):
    '''Get incidents by access token and ranges'''
    data = {}
    responsecode = 200
    headerz = {"Authorization" : "Bearer {}".format(accesstoken) , "Content-Type": "application/json"}
    urlz = 'https://{}/dlp/rest/v1/incidents'.format(dlpfsmurl)
    ## Retrieve incident only for policy "catchthis" and with status: "New".
    data = '{ "type" : "INCIDENTS", "status" : "NEW",  "policies" : "catchthis", "from_date" : "01/01/2023 00:00:00", "to_date" : "31/12/2023 23:59:59" }'
 
    r={}
    try:
        r = requests.post(urlz, headers=headerz, data=data, verify=False)
        response = json.loads(r.text)
        if r.ok : 
            responsecode = 200
        else :
            responsecode = r.status_code

        return response, responsecode
    except requests.exceptions.RequestException as err:
        print (err)
        sys.exit()

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
        sys.exit()

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
        sys.exit()

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
def writetofile(incidents_bulk,incidents_results_full_path,accesstoken, dlpfsmurl):
    now = datetime.now() # current date and time
    date_time = now.strftime("_%m-%d-%Y-%H-%M-%S")

    ## TODO::  add path for windows or linux with if statement selection 
    filename = incidents_results_full_path + 'DLP_incidnets' + date_time + '.log'
    incident_list = incidents_bulk.get('incidents')

    file=open(filename, mode="wt", encoding='utf-8')
    for items in incident_list:
        # close FALSE POSITIVE incidents for policy:
        print (items)
        incident_id = items['id']
        partition_id = items['partition_index']
        responsecode = update_incident(accesstoken,dlpfsmurl, incident_id, partition_id,
                                       'INCIDENTS', 'STATUS', 'CLOSE',False)
        if (responsecode < 300):
            print('closed {} '.format(str(incident_id)))


        # Write to file
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

    POLLING_INTERVAL_MINUTES = 5 #Not suitable for production

    username  = ''
    password  =  ''
    dlpfsmurl = ''
    accesstoken = ''
    incidents_results_full_path  =  ''  #  Full path to results folder.
# TBD add these variables to the functions:
    valid_certificate = False
    logged_incident_type = 'INCIDENTS'
    configfile = 'restapi.conf'
    # polling interval of 1 minute is for debugging/demo only.
    # for production environment please set 5 or 10m ( 5 * 60 )
    polling_interval = POLLING_INTERVAL_MINUTES * 60 # seconds

    logging.basicConfig(
     filename='DLPAPI.log',
     level=logging.INFO,
     format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
     datefmt='%H:%M:%S' )

    logger = logging.getLogger(__name__)
    #Testing our Logger
    logger.info("DLP RestAPI started")

    logger.info("Read Config file")
    username, password, dlpfsmurl,incidents_results_full_path, valid_certificate, \
    logged_incident_type, servicenow_enabled, servicenow_instance, servicenow_user, \
    servicenow_password, servicenow_create_incident_from = read_config(configfile)

    if ( (username) and (password) and (dlpfsmurl) and (incidents_results_full_path)):
        logger.info("Config file ok")
    else:
        logger.error("Bad Config file")
        sys.exit()

    # get initial token
    refreshtoken = getrefreshtoken(username,password,dlpfsmurl,valid_certificate)
    if (refreshtoken is not None):
        logger.info("Auth token retrieved")
    else:
        logger.error("Bad authentication. please check your config file and try again.")
        print("Bad authentication. please check your config file and try again.")
        sys.exit()

    # get access token
    accesstoken = getnewaccesstoken(refreshtoken,dlpfsmurl,valid_certificate)
    accesstokenvalid = True
    if (accesstokenvalid):
        start_tf, end_tf = get_time_frame_for_next_request(datetime.timestamp, polling_interval ) #5 min

        incidents_bulk, responsecode = retrieve_incidents_for_tf(accesstoken,dlpfsmurl, start_tf, end_tf,valid_certificate, logged_incident_type)
        logger.info('request for {} returned status code: {}'.format(logged_incident_type, responsecode))
        accesstokenvalid = check_validity_at(responsecode)
        # incidents items clount
        if (accesstokenvalid and incidents_bulk['total_count'] > 0):
            logger.info('Retrieved {} matching incidents'.format(incidents_bulk['total_count']))
            print('DEBUG MSG: Retrieved {} matching incidents'.format(incidents_bulk['total_count']))
            status =writetofile(incidents_bulk,incidents_results_full_path,
                                # extra params for closing incidents automatically.
                                accesstoken,dlpfsmurl)
            logger.info(status)
            if (servicenow_enabled):
                logger.info('Pushing {} incidents to Servicenow instance: {}'.format(servicenow_instance, len(incidents_bulk['incidents'])))
                push_status = servicenow_incident.push_incidents_to_servicenow(servicenow_instance, servicenow_user, servicenow_password,incidents_bulk, servicenow_create_incident_from)
                logger.info('ServiceNow API returned status: {}'.format(push_status))

################################
# Main call
#  Eran Amir 2023 (c)
################################
if __name__ == "__main__":
    main()