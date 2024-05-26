"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve information about a domain from the VirusTotal API.

Documentation:

    * v3 documentation - https://developers.virustotal.com/reference/domain-info

    * v2 documentation - https://developers.virustotal.com/v2.0/reference/domain-report
"""

from virustotal_python import Virustotal
from pprint import pprint

API_KEY = "<VirusTotal API Key>"

domain = "virustotal.com"

# v3 example
vtotal = Virustotal(API_KEY=API_KEY)
resp = vtotal.request(f"domains/{domain}")
pprint(resp.data)

# v2 example
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION=2)
resp = vtotal.request("domain/report", params={"domain": domain})
print(resp.response_code)
pprint(resp.json())
