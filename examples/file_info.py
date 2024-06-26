"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve information about a file from the VirusTotal API.

Documentation:

    * v3 documentation - https://developers.virustotal.com/reference/file-info

    * v2 documentation - https://developers.virustotal.com/v2.0/reference/file-report
"""

from virustotal_python import Virustotal
from pprint import pprint

API_KEY = "<VirusTotal API Key>"

# The ID (either SHA-256, SHA-1 or MD5 hash) identifying the file
FILE_ID = "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"

# v3 example
vtotal = Virustotal(API_KEY=API_KEY)
resp = vtotal.request(f"files/{FILE_ID}")
pprint(resp.data)

# v2 example
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION=2)
resp = vtotal.request("file/report", {"resource": FILE_ID})
print(resp.response_code)
pprint(resp.json())
