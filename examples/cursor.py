"""
The examples in this file are for virustotal-python version >=0.1.0

Use a cursor from the VirusTotal API response JSON to retrieve more results.

Documentation:

    * v3 documentation - https://developers.virustotal.com/v3.0/reference#collections
"""
from virustotal_python import Virustotal
from pprint import pprint

API_KEY = "Insert API key here."

# The ID (either SHA-256, SHA-1 or MD5) identifying the file
FILE_ID = "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"

# v3 example
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

# Retrieve communicating_files related to the IP address with a limit of 5
resp = vtotal.request(f"ip_addresses/{IP}/communicating_files", params={"limit": 2})

count = 0

# While a cursor is present, keep collecting results!
while resp.cursor:
    print(count)
    print(f"This is the current: {resp.cursor}")
    # Get more results with cursor
    resp = vtotal.request(f"ip_addresses/{IP}/communicating_files", params={"limit": 2, "cursor": resp.cursor})
    # Do something with the resp here
    # Add to count to show how many times we have got another cursor
    count += 1
