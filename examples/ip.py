"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve IP addresses using the VirusTotal API.

Documentation:

    * v3 documentation

    https://developers.virustotal.com/reference/ip-info
    https://developers.virustotal.com/reference/ip-object#relationships
    https://developers.virustotal.com/reference/ip-votes-post

    * v2 documentation - https://developers.virustotal.com/v2.0/reference/ip-address-report
"""
from virustotal_python import Virustotal
from pprint import pprint

API_KEY = "<VirusTotal API Key>"

# (Google DNS)
IP = "8.8.8.8"

# v3 examples
vtotal = Virustotal(API_KEY=API_KEY)

# Get information about an IP address
resp = vtotal.request(f"ip_addresses/{IP}")
# Get objects (relationships) related to an IP address
# Get historical_whois relationship to the IP address
resp = vtotal.request(f"ip_addresses/{IP}/historical_whois")
# Get communicating_files related to the IP address with a limit of 5
resp = vtotal.request(f"ip_addresses/{IP}/communicating_files", params={"limit": 5})

# Get votes for an IP address
resp = vtotal.request(f"ip_addresses/{IP}/votes")
# Add a vote for an IP address
# Verdict can be either harmless or malicious
vote = {"data": {"type": "vote", "attributes": {"verdict": "harmless"}}}
resp = vtotal.request(f"ip_addresses/{IP}/votes", json=vote, method="POST")

# v2 examples
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION=2)
# Get information about an IP address
resp = vtotal.request("ip-address/report", params={"ip": IP})
pprint(resp.json())
