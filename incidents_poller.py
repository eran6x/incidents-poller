import json
import time
import logging
import requests
from datetime import datetime

__author__ = 'Eran Amir 2022'

################################
# TBD 1) add verify certificate flag.

################################
# Read config From file
#
################################
def read_config(configfile):
    # Using readlines()
    file1 = open(configfile, 'r')
    Lines = file1.readlines()

    count = 0
    # Strips the newline character
    for line in Lines:
        count += 1
        line0 = line.split('=')[0]
        line1 = (line.split('=')[1])
        line1 = line1. rstrip("\n")
        #print("Line{}: arg0= {} arg 1= {}".format(count, line0,line1))

        if line0.lower() in ['hostname', 'Hostname']:
            dlpfsmurl = line1
        elif line0.lower() in ['username', 'Username']:
            username = line1
        elif line0.lower() in ['password', 'Password']:
            password = line1
        elif line0.lower() in ['location', 'Location']:
            incidents_results_full_path = line1
        else:
            pass
    return username, password, dlpfsmurl, incidents_results_full_path

################################
# Get a <Refresh Token> from 
#  credentials.
################################
def getrefreshtoken(username,password,dlpfsmurl):
    headerz = {"username" : username, "password" : password}
    urlz = 'https://{}/dlp/rest/v1/auth/refresh-token'.format(dlpfsmurl)
    r={}
    try:
        r = requests.post(urlz,headers=headerz,verify=False)
        response = json.loads(r.text)
        print('Refresh token = {}'.format(response["refresh_token"][-10:0]))
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
def getnewaccesstoken(refreshtoken,dlpfsmurl):
    #data = {}
    headerz = {"refresh-token" : "Bearer {}".format(refreshtoken) }
    urlz = 'https://{}/dlp/rest/v1/auth/access-token'.format(dlpfsmurl)
    r={}
    try:
        r = requests.post(urlz,headers=headerz,verify=False)
        response = json.loads(r.text)
        print('Access token = {}'.format(response["access_token"][-10:0]))
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
    
    #s_from_date = "01/01/2022 00:00:00"
    #s_to_date   = "04/01/2022 23:59:59"
    
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
    filename = incidents_results_full_path + '/DLP_incidnets' + date_time
    incident_list = incidents_bulk.get('incidents')

    with open(filename, mode="wt", encoding='utf-8') as f:
        f.write('\n'.join(incident_list))
#    with open(filename, "w+") as f:
        # incidents_bulk.items().len()
        #f.writelines(incidents_bulk.items())
        #f.close


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
    valid_certificate = False
    configfile = 'restapi.conf'
    
    print("DLP RestAPI start \n")

    logging.basicConfig(
     filename='DLPAPI.log',
     level=logging.INFO, 
     format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
     datefmt='%H:%M:%S' )
    
    logger = logging.getLogger(__name__)
    #Testing our Logger
    logger.info("DLP RestAPI start")

    logger.info("Read Config file")
    username, password, dlpfsmurl,incidents_results_full_path = read_config(configfile)
    if ( (username) and (password) and (dlpfsmurl) and (incidents_results_full_path)):
        logger.info("Config file ok")
    else :
        logger.error("Bad Config file")
        exit
        
    # get initial token 
    refreshtoken = getrefreshtoken(username,password,dlpfsmurl)

    # get access token
    accesstoken = getnewaccesstoken(refreshtoken,dlpfsmurl)
    accesstokenvalid = False
        
    # DISABLED workaround for testing incidents: 
    #incidents_bulk = retrieve_incidents2multipart(accesstoken,dlpfsmurl)
    #if incidents_bulk: writetofile(incidents_bulk,incidents_results_full_path)

############################################################################
#
# This part is an endless loop where we try to retrieve the next incidents
# 
    #timestamp1 = datetime.timestamp
    while (True):
        if (accesstokenvalid):
            incidents_bulk, responsecode = retrieve_incidents(accesstoken,dlpfsmurl)
            accesstokenvalid = check_validity_at(responsecode)
            # TBD change this to items clount
            if (incidents_bulk['total_count'] > 0): 
                writetofile(incidents_bulk,incidents_results_full_path)
        else:
            accesstoken = getnewaccesstoken(refreshtoken,dlpfsmurl)
            if (accesstoken) : accesstokenvalid = True
            
        time.sleep(60) #wait one mintue until next iteration



################################
# Main call 
#  Eran Amir 2021 (c) 
################################
if __name__ == "__main__":
    main()