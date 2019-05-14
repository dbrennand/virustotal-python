"""
MIT License

Copyright (c) 2019 Daniel Brennand (Dextroz)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""
try:
    from requests import get, post
    from os.path import abspath, basename
except ImportError:
    print(f"Failed to import required modules: {err}")


class Virustotal(object):
    """
    Base class for interacting with the Virustotal Public API. (https://www.virustotal.com/en/documentation/public-api/)
    """

    def __init__(self, API_KEY=None, PROXIES=None):
        self.API_KEY = API_KEY
        self.PROXIES = PROXIES
        self.BASEURL = "https://www.virustotal.com/vtapi/v2/"
        self.VERSION = "0.0.6"
        self.headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": f"gzip,  virustotal-python {self.VERSION}",
        }
        if API_KEY is None:
            raise ValueError(
                "An API_KEY is required to interact with the VirusTotal API."
            )

    def file_scan(self, file):
        """
        Send a file to Virustotal for analysis. (https://www.virustotal.com/en/documentation/public-api/#scanning-files)
           :param file: The path to the file to be sent to Virustotal for analysis.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY}
        files = {"file": (basename(file), open(abspath(file), "rb"))}
        resp = self.make_request(
            f"{self.BASEURL}file/scan", params=params, files=files, proxies=self.PROXIES
        )
        return resp

    def file_rescan(self, *resource: list):
        """
        Resend a file to Virustotal for analysis. (https://www.virustotal.com/en/documentation/public-api/#rescanning-files)
           :param *resource: A list of resource(s) of a specified file(s). Can be `md5/sha1/sha256 hashes`. Can be a combination of any of the three allowed hashes (MAX 25 items).
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "resource": ",".join(*resource)}
        resp = self.make_request(
            f"{self.BASEURL}file/rescan", params=params, proxies=self.PROXIES
        )
        return resp

    def file_report(self, *resource: list):
        """
        Retrieve scan report(s) for a given file from Virustotal. (https://www.virustotal.com/en/documentation/public-api/#getting-file-scans)
           :param *resource: A list of resource(s) of a specified file(s). Can be `md5/sha1/sha256 hashes` and/or combination of hashes and scan_ids (MAX 4 per standard request rate).
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "resource": ",".join(*resource)}
        resp = self.make_request(
            f"{self.BASEURL}file/report",
            params=params,
            method="GET",
            proxies=self.PROXIES,
        )
        return resp

    def url_scan(self, *url: list):
        """
        Send url(s) to Virustotal. (https://www.virustotal.com/en/documentation/public-api/#scanning-urls)
           :param *url: A list of url(s) to be scanned. (MAX 4 per standard request rate).
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "url": "\n".join(*url)}
        resp = self.make_request(
            f"{self.BASEURL}url/scan", params=params, proxies=self.PROXIES
        )
        return resp

    def url_report(self, *resource: list, scan=None):
        """
        Retrieve scan report(s) for a given url(s) (https://www.virustotal.com/en/documentation/public-api/#getting-url-scans)
           :param *resource: A list of the url(s) and/or scan_id(s) report(s) to be retrieved (MAX 4 per standard request rate).
           :param scan: An optional parameter. When set to "1" it will automatically submit the URL for analysis if no report is found for it in VirusTotal's database.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "resource": "\n".join(*resource)}
        if scan is not None:
            params["scan"] = scan
        resp = self.make_request(
            f"{self.BASEURL}url/report", params=params, proxies=self.PROXIES
        )
        return resp

    def ipaddress_report(self, ip):
        """
        Retrieve a scan report for a specific ip address. (https://www.virustotal.com/en/documentation/public-api/#getting-ip-reports)
           :param ip: A valid IPV4 address in dotted quad notation.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "ip": ip}
        resp = self.make_request(
            f"{self.BASEURL}ip-address/report",
            params=params,
            method="GET",
            proxies=self.PROXIES,
        )
        return resp

    def domain_report(self, domain):
        """
        Retrieve a scan report for a specific domain name. (https://www.virustotal.com/en/documentation/public-api/#getting-domain-reports)
           :param domain: A domain name.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "domain": domain}
        resp = self.make_request(
            f"{self.BASEURL}domain/report",
            params=params,
            method="GET",
            proxies=self.PROXIES,
        )
        return resp

    def put_comment(self, resource, comment):
        """
        Make comments on files and URLs. (https://www.virustotal.com/en/documentation/public-api/#making-comments)
           :param resource: The `md5/sha1/sha256 hash` of the file you want to review or the URL itself that you want to comment on.
           :param comment: The str comment to be submitted.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "resource": resource, "comment": comment}
        resp = self.make_request(
            f"{self.BASEURL}comments/put", params=params, proxies=self.PROXIES
        )
        return resp

    def make_request(self, endpoint, params, method="POST", **kwargs):
        """
        Helper function to make the request to the specified endpoint.
           :param endpoint: The specific Virustotal API endpoint.
           :param method: The request method to use.
           :param params: The parameters to go along with the request.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        if method == "POST":
            resp = post(endpoint, params=params, headers=self.headers, **kwargs)
        elif method == "GET":
            resp = get(endpoint, params=params, headers=self.headers, **kwargs)
        else:
            raise ValueError("Invalid request method.")
        return self.validate_response(resp)

    def validate_response(self, response):
        """
        Helper function to validate the response request produced from make_request().
           :param response: The requests response object.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        if response.status_code == 200:
            json_resp = response.json()
            return dict(status_code=response.status_code, json_resp=json_resp)
        else:
            return dict(
                status_code=response.status_code,
                error=response.text,
                resp=response.content,
            )
