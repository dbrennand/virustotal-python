"""
The examples in this file are for virustotal-python version >=0.1.0

Send a file to VirusTotal for analysis.

Documentation:

    * v2 documentation - https://www.virustotal.com/en/documentation/public-api/

    * v3 documentation - https://developers.virustotal.com/v3.0/reference
"""
from virustotal_python import Virustotal
import os.path
from pprint import pprint

API_KEY = "Insert API key here."

# v3 example
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

# Declare PATH to file
FILE_PATH = "/path/to/file/to/scan.txt"

# Create dictionary containing the file to send for multipart encoding upload
files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}

resp = vtotal.request("files", files=files, method="POST")

pprint(resp.data)

# v2 example
vtotal = Virustotal(API_KEY=API_KEY)

# Declare PATH to file
FILE_PATH = "/path/to/file/to/scan.txt"

# Create dictionary containing the file to send for multipart encoding upload
files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}

resp = vtotal.request("file/scan", files=files, method="POST")

print(resp.response_code)
pprint(resp.json())