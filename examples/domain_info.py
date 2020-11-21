"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve information about a domain from the VirusTotal API.

Documentation:

    * v2 documentation - https://developers.virustotal.com/reference#domain-report

    * v3 documentation - https://developers.virustotal.com/v3.0/reference#domain-info
"""
from virustotal_python import Virustotal
from pprint import pprint

API_KEY = "Insert API key here."

domain = "virustotal.com"

# v2 example
vtotal = Virustotal(API_KEY=API_KEY)

resp = vtotal.request("domain/report", params={"domain": domain})

print(resp.response_code)
pprint(resp.json())

# v3 example
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

resp = vtotal.request(f"domains/{domain}")

pprint(resp.data)
