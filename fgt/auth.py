##############################################################
##
##
## DEFAULT LOGIN & LOGOUT SCRIPT
##
##
##############################################################
import requests
import urllib3
import pprint
import json
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

##############################################################
## GET BASE INFORMATION
##############################################################
username = input('Enter username: ')
password = input('Enter password: ')
credentials = [
  ('username', username),
  ('secretkey', password),
]

api_key = "gspdrc1y6cHjd6xg1tHpdstjc0ysfq"
ip_address = "172.31.40.200"
port = "444"
url_login = 'https://{}:{}/logincheck'.format(ip_address, port)
url_logout = 'https://{}:{}/logout'.format(ip_address, port)
headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
}

##############################################################
## LOGIN AND GET THE COOKIE
##############################################################
session = requests.session()
get_cookie = session.post(url_login, data=credentials, verify=False, timeout=2)

print("Login Status", get_cookie.status_code)
if get_cookie.status_code == 200:
    print("LOGIN SUCCESS!")
else:
    print("SOMETHING WENT WRONG!")

print("")

ccsrfrtoken = get_cookie.cookies['ccsrftoken']
ccsrfrtoken = ccsrfrtoken.replace('"','')
print("CSRFTOKEN = {}".format(ccsrfrtoken))

##############################################################
## GET INFO, BUT FIRST DEFINE URL AND HEADERS
##############################################################

url = 'https://{}:{}/api/v2'.format(ip_address, port)
#headers = {'Authorization': 'Bearer ' + api_key}
headers = {
    'X-CSRFTOKEN': ccsrfrtoken,
    'Content-Type': "application/json",
    'Cache-Control': "no-cache",
}

#params = {'vdom': "root"}
print("URL = {}".format(url) + "/monitor/firewall/policy")
print("Headers = {}".format(headers))
#print(params)

get_policy = requests.session()
result = get_policy.get(url + "/monitor/firewall/policy", headers=headers, verify=False, timeout=2)

print(result.status_code)


##############################################################
## LOGOUT AND GOODBYE
##############################################################
delete_session = session.delete(url_logout, verify=False, timeout=2)
print("Logout Status: {}".format(delete_session.status_code))
if delete_session.status_code == 200:
    print("LOGOUT SUCCESS - GOODBYE!!!")
else:
    print("LOGOUT WASN'T SUCCESSFUL")
