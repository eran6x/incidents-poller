'''
Create Incidents in Servicenow instance according to pulled incidents details.
@Author Eran Amir, (Eran.Amir@forcepoint.com)
@ Year 2022


'''
import requests
import json

def dummy_input():
    incident = { 'id':'6760673', 'severity': 'HIGH', 'action': 'BLOCKED', 'status': 'New', 'source': {'manager': 'Dave Roberts', 'login_name': 'PRES3NT\\will', 'host_name': 'Win10-GV.pres3nt.local', 'business_unit': 'High risk Users'}, 'history': [{...}, {...}], 'event_id': '5379011321656598049', 'maximum_matches': 3, 'transaction_size': 36537, 'analyzed_by': 'Policy Engine  srv-fs3nt.local', 'ignored_incidents': False, 'event_time': '23/09/2022 22:13:48', 'incident_time': '23/09/2022 22:14:24',
             'channel': 'ENDPOINT_HTTPS', 'destination':'DLPTEST.COM','policies':'KSA ; France PII; Germany PII'}
    formatted_incident = format_request_body(incident, 'IntegrationUser')
    push_incident('dev91718', 'IntegrationUser', 'Forcepoint1!', formatted_incident)


def format_request_body(incident, servicenow_user):
    caller_id = servicenow_user
    short_description = f"DLP IncidentID:{incident['id']}.Triggered policies:{incident['policies']} . Destination:{incident['destination']}. Detected by:{incident['channel']}"
    category = "Software"
    raw_impact = incident["severity"]
    if (raw_impact=="LOW"):
        impact = "3- Low"
    if (raw_impact=="MEDIUM"):
        impact = "2- Medium"
    if (raw_impact=="HIGH"):
        impact = "1 - High"

    request_body = f"\"caller_id\":\"{caller_id}\",\"category\":\"Software\",\"impact\":\"{impact}\",\"short_description\":\"{short_description}\",\"subcategory\":\"Email\""

    request_body2 = '{' + request_body + '}'
    return request_body2

def push_incidents_to_servicenow(servicenow_instance, servicenow_user, servicenow_password,incidents_bulk):
    print('push {} incidents to {}'.format(str(len(incidents_bulk['incidents'])), servicenow_instance))
    last_response_code = 200
    for incident in incidents_bulk['incidents']:
        request_body = format_request_body(incident, servicenow_user)
        last_response_code = push_incident(servicenow_instance, servicenow_user, servicenow_password,request_body)
    return last_response_code

def push_incident(servicenow_instance, user, pwd,incident):
    # Set the request parameters
    url = 'https://{}.service-now.com/api/now/table/incident'.format(servicenow_instance)

    # Set proper headers
    headers = {"Content-Type":"application/json","Accept":"application/json"}

    # Do the HTTP request
    response={}
    try:
        response = requests.post(url, auth=(user, pwd), headers=headers ,data=incident)
    except Exception as err:
        print (err)
        # exit
    # print(str(response.status_code))

    if response.status_code > 201: # accepted/partial
        print('ERROR:\nStatus:', response.status_code,
            '\nHeaders:', response.headers,
            '\nError Response:',response.json())

    return response.status_code

def tester():
    dummy = "{\"caller_id\":\"Abel Tuter\",\"short_description\":\"Integration24 short description\",\"category\":\"Software\",\"impact\":\"2 - Medium\"}"
    #push_incident(dummy)

################################
# Main call 
#  Eran Amir 2021 (c) 
################################
if __name__ == "__main__":
   dummy_input()
   # tester()