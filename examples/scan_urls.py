"""
The examples in this file are for virustotal-python version >=0.1.0

Send URLs to the VirusTotal API for analysis and retrieve the analysis results.

Documentation:

    * v3 documentation

        https://developers.virustotal.com/reference/scan-url
        https://developers.virustotal.com/reference/url-info

    * v2 documentation

        https://developers.virustotal.com/v2.0/reference/url-scan
        https://developers.virustotal.com/v2.0/reference/url-report
"""

from virustotal_python import Virustotal
from pprint import pprint
from base64 import urlsafe_b64encode

API_KEY = "<VirusTotal API Key>"

URLS = ["google.com", "wikipedia.com", "github.com"]

# v3 example
vtotal = Virustotal(API_KEY=API_KEY)

for url in URLS:
    resp = vtotal.request("urls", data={"url": url}, method="POST")
    # Safe encode URL in base64 format
    # https://developers.virustotal.com/reference/url
    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
    print(f"URL: {url} ID: {url_id}")
    report = vtotal.request(f"urls/{url_id}")
    print(report.object_type)
    pprint(report.data)

# v2 example
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION=2)

# A maximum of 4 URLs can be sent at once for a v2 API request
resp = vtotal.request("url/scan", params={"url": "\n".join(URLS)}, method="POST")
for url_resp in resp.json():
    scan_id = url_resp["scan_id"]
    print(scan_id)
    # Request report for URL analysis
    analysis_resp = vtotal.request("url/report", params={"resource": scan_id})
    print(analysis_resp.response_code)
    pprint(analysis_resp.json())
