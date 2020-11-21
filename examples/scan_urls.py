"""
The examples in this file are for virustotal-python version >=0.1.0

Send URLs to the VirusTotal API for analysis and retrieve the analysis results.

Documentation:

    * v2 documentation - https://developers.virustotal.com/reference#url-scan

        * https://developers.virustotal.com/reference#url-report

    * v3 documentation - https://developers.virustotal.com/v3.0/reference#urls

        * https://developers.virustotal.com/v3.0/reference#url-info
"""
from virustotal_python import Virustotal
import os.path
from pprint import pprint
from base64 import urlsafe_b64encode

API_KEY = "Insert API key here."

URLS = ["google.com", "wikipedia.com", "github.com", "ihaveaproblem.info"]

# v2 example
vtotal = Virustotal(API_KEY=API_KEY)

# Send the URLs to VirusTotal for analysis
# A maximum of 4 URLs can be sent at once for a v2 API request
resp = vtotal.request("url/scan", params={"url": "\n".join(url)}, method="POST")
for url_resp in resp.json():
    # Obtain scan_id
    scan_id = url_resp["scan_id"]
    # Request report for URL analysis
    analysis_resp = vtotal.request("url/report", params={"resource": scan_id})
    print(analysis_resp.response_code)
    pprint(analysis_resp.json())

# v3 example
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

for url in URLS:
    # Send the URL to VirusTotal for analysis
    resp = vtotal.request("urls", data={"url": url}, method="POST")
    # URL safe encode URL in base64 format
    # https://developers.virustotal.com/v3.0/reference#url
    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
    print(f"URL: {url} ID: {url_id}")
    # Obtain the analysis results for the URL using the url_id
    analysis_resp = vtotal.request(f"urls/{url_id}")
    print(analysis_resp.object_type)
    pprint(analysis_resp.data)
