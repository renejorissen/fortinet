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
import getpass
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

ip_address = "10.10.50.1"
port = "444"
url_login = 'https://{}:{}/logincheck'.format(ip_address, port)
url_logout = 'https://{}:{}/logout'.format(ip_address, port)
headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
}


#curl -k -v -c fgt.txt -d username=admin -d secretkey=PASSWORD "https://192.168.128.2:4443/logincheck"
#curl -k --cookie fgt.txt -i -H "Accept: application/json" -H "Content-Type: application/json" -X GET "https://192.168.128.2:4443/api/v2/monitor/router/ipv4/"


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
cookie = get_cookie.cookies
items = cookie.items()

for name, value in items:
    print(name, value)



##############################################################
## LOGOUT AND GOODBYE
##############################################################
delete_session = session.delete(url_logout, verify=False, timeout=2)
print("Logout Status: {}".format(delete_session.status_code))
if delete_session.status_code == 200:
    print("LOGOUT SUCCESS - GOODBYE!!!")
else:
    print("LOGOUT WASN'T SUCCESSFUL")
