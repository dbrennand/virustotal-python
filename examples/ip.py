"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve IP addresses using the VirusTotal API.

Documentation:

    * v2 documentation - https://developers.virustotal.com/reference#ip-address-report

    * v3 documentation - https://developers.virustotal.com/v3.0/reference#ip-addresses
"""
from virustotal_python import Virustotal
from pprint import pprint

API_KEY = "Insert API key here."

# Example IP address (Google DNS)
IP = "8.8.8.8"

# v3 examples
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

# Retrieve information about an IP address
resp = vtotal.request(f"ip_addresses/{IP}")
# Retrieve objects (relationships) related to an IP address
# Retrieve historical_whois relationship to the IP address
# For other relationships, see the table at: https://developers.virustotal.com/v3.0/reference#ip-relationships
resp = vtotal.request(f"ip_addresses/{IP}/historical_whois")
# Retrieve communicating_files related to the IP address with a limit of 5
resp = vtotal.request(
    f"ip_addresses/{IP}/communicating_files", params={"limit": 5})

# Retrieve votes for an IP address
resp = vtotal.request(f"ip_addresses/{IP}/votes")
# Send a vote for an IP address
# Create vote JSON
## Verdict can be either harmless or malicious
### https://developers.virustotal.com/v3.0/reference#ip-votes-post
vote = {"data": {"type": "vote", "attributes": {"verdict": "harmless"}}}
resp = vtotal.request(f"ip_addresses/{IP}/votes", json=vote, method="POST")
