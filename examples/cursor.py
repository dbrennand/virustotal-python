"""
The examples in this file are for virustotal-python version >=0.1.0

Use a cursor from the VirusTotal API JSON response to retrieve more results.

Documentation:

    * v3 documentation - https://developers.virustotal.com/reference/collections
"""
from virustotal_python import Virustotal

API_KEY = "<VirusTotal API Key>"
#  (Google DNS)
IP = "8.8.8.8"

# v3 example
vtotal = Virustotal(API_KEY=API_KEY)

# Get communicating_files related to the IP address with a limit of 2
resp = vtotal.request(f"ip_addresses/{IP}/communicating_files", params={"limit": 2})

count = 0
# While a cursor is present, keep collecting results!
while resp.cursor:
    print(f"Current count: {count} - Cursor: {resp.cursor}")
    # Get more results using the cursor
    resp = vtotal.request(
        f"ip_addresses/{IP}/communicating_files",
        params={"limit": 2, "cursor": resp.cursor},
    )
    # Do something with the resp here
    # Add to the count to show how many times we have retrieved another cursor
    count += 1
