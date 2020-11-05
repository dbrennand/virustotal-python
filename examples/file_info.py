"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve information about a file from the VirusTotal API.

Documentation:

    * v2 documentation - https://www.virustotal.com/en/documentation/public-api/

    * v3 documentation - https://developers.virustotal.com/v3.0/reference
"""
from virustotal_python import Virustotal
from pprint import pprint

# v3 example
API_KEY = "Insert API key here."

# The ID (either SHA-256, SHA-1 or MD5) identifying the file
FILE_ID = "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85"

vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

resp = vtotal.request(f"files/{FILE_ID}")

pprint(resp.data)

# v2 example
vtotal = Virustotal(API_KEY=API_KEY)

resp = vtotal.request("file/report", {"resource": FILE_ID})

print(resp.response_code)
pprint(resp.json())
