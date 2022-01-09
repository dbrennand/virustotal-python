"""
The examples in this file are for virustotal-python version >=0.1.0

Send a file to the VirusTotal API for analysis.

Documentation:

    * v2 documentation - https://developers.virustotal.com/reference#file-scan

    * v3 documentation - https://developers.virustotal.com/v3.0/reference#files-scan

        * https://developers.virustotal.com/reference/files-upload-url
"""
from virustotal_python import Virustotal
import os.path
from pprint import pprint

API_KEY = "Insert API key here."

# Declare PATH to file
FILE_PATH = "/path/to/file/to/scan.txt"

# Create dictionary containing the file to send for multipart encoding upload
files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}

# v2 example
vtotal = Virustotal(API_KEY=API_KEY)

resp = vtotal.request("file/scan", files=files, method="POST")

print(resp.response_code)
pprint(resp.json())

# v3 example
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

resp = vtotal.request("files", files=files, method="POST")

pprint(resp.data)

# v3 example for uploading a file larger than 32MB in size
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

# Create dictionary containing the large file to send for multipart encoding upload
large_file = {"file": (os.path.basename("/path/to/file/larger/than/32MB"), open(os.path.abspath("/path/to/file/larger/than/32MB"), "rb"))}
# Get URL to send a large file
upload_url = vtotal.request("files/upload_url").data
# Submit large file to VirusTotal v3 API for analysis
resp = vtotal.request(upload_url, files=large_file, method="POST", large_file=True)
pprint(resp.data)
