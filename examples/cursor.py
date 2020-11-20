"""
The examples in this file are for virustotal-python version >=0.1.0

Use a cursor from the VirusTotal API JSON response to retrieve more results.

Documentation:

    * v3 documentation - https://developers.virustotal.com/v3.0/reference#collections
"""
from virustotal_python import Virustotal
from pprint import pprint

API_KEY = "Insert API key here."

# Example IP address (Google DNS)
IP = "8.8.8.8"

# v3 example
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

# Retrieve communicating_files related to the IP address with a limit of 5
resp = vtotal.request(f"ip_addresses/{IP}/communicating_files", params={"limit": 2})

# Initialise count variable
count = 0

# While a cursor is present, keep collecting results!
while resp.cursor:
    print(count)
    print(f"This is the current: {resp.cursor}")
    # Get more results with cursor
    resp = vtotal.request(f"ip_addresses/{IP}/communicating_files", params={"limit": 2, "cursor": resp.cursor})
    # Do something with the resp here
    # Add to the count to show how many times we have retrieved another cursor
    count += 1
