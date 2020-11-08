"""
The examples in this file are for virustotal-python version >=0.1.0

Search the VirusTotal v3 API for domains, IP addresses, comments and URL.

Also, retrieve VirusTotal metadata.

Documentation:

    * v3 documentation - https://developers.virustotal.com/v3.0/reference#search-1

        * https://developers.virustotal.com/v3.0/reference#metadata
"""
from virustotal_python import Virustotal
from pprint import pprint

API_KEY = "Insert API key here."

# The ID (either SHA-256, SHA-1 or MD5) identifying the file
FILE_ID = "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"

# v3 examples
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

## Search the VirusTotal API for google.com
resp = vtotal.request("search", params={"query": "google.com"})
## Search the VirusTotal API for information related to Google's DNS (8.8.8.8)
resp = vtotal.request("search", params={"query": "8.8.8.8"})
## Search the VirusTotal API for a file ID
resp = vtotal.request("search", params={"query": FILE_ID})
## Search the VirusTotal API for the tag comment '#malicious'
resp = vtotal.request("search", params={"query": "#malicious"})

## Retrieve VirusTotal metadata
resp = vtotal.request("metadata")
## Print out a list of VirusTotal's supported engines
resp = vtotal.request("metadata")
engines_dict = resp.data["engines"]
print(engines_dict.keys())
