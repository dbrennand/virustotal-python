"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve information about a file from the VirusTotal API.

Documentation:

    * v2 documentation - https://developers.virustotal.com/reference#file-report

    * v3 documentation - https://developers.virustotal.com/v3.0/reference#file-info
"""
from virustotal_python import Virustotal
from pprint import pprint

# v3 example
API_KEY = "Insert API key here."

# The ID (either SHA-256, SHA-1 or MD5) identifying the file
FILE_ID = "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"

vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

resp = vtotal.request(f"files/{FILE_ID}")

pprint(resp.data)

# v2 example
vtotal = Virustotal(API_KEY=API_KEY)

resp = vtotal.request("file/report", {"resource": FILE_ID})

print(resp.response_code)
pprint(resp.json())
