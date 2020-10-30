"""
MIT License

Copyright (c) 2020 dbrennand

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
SOFTWARE.
"""
from requests import get, post
from os.path import abspath, basename


class Virustotal(object):
    """
    Base class for interacting with the public VirusTotal API [v2](https://www.virustotal.com/en/documentation/public-api/) and [v3](https://developers.virustotal.com/v3.0/reference).
    """

    def __init__(
        self, API_KEY: str = None, PROXIES: dict = None, API_VERSION: str = "v2"
    ):
        """
        Initalisation method for Virustotal class.

        :param API_KEY: The API used to interact with the VirusTotal v2 and v3 APIs.
        :param PROXIES: A dictionary object containing proxies used when making requests.
        :param API_VERSION: The version to use when interacting with the VirusTotal API. This parameter defaults to 'v2' for backwards compatibility.
        :raises ValueError: Raises ValueError when no API_KEY is provided or the API_VERSION is invalid.
        """
        self.VERSION = "0.1.0"
        self.API_KEY = API_KEY
        if API_KEY is None:
            raise ValueError(
                "An API_KEY is required to interact with the VirusTotal API."
            )
        self.PROXIES = PROXIES
        # Declare appropriate variables depending on the API_VERSION provided
        if API_VERSION == "v2":
            self.API_VERSION = API_VERSION
            self.BASEURL = "https://www.virustotal.com/vtapi/v2/"
            self.HEADERS = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": f"gzip,  virustotal-python {self.VERSION}",
            }
        elif API_VERSION == "v3":
            self.API_VERSION = API_VERSION
            self.BASEURL = "https://www.virustotal.com/api/v3/"
            self.HEADERS = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": f"gzip, virustotal-python {self.VERSION}",
                "x-apikey": f"{self.API_KEY}",
            }
        else:
            raise ValueError(
                f"The API version {API_VERSION} is not a valid VirusTotal API version.\nValid API versions are: 'v2' or 'v3'."
            )

    def file_scan(self, file, upload_url: str = None):
        """
        Send a file to VirusTotal for analysis. Max file size is 32MB.

        [v2 documentation](https://developers.virustotal.com/v2.0/reference#file-scan)

        [v3 documentation](https://developers.virustotal.com/v3.0/reference#files-scan)

        :param file: The path to the file to be sent to VirusTotal for analysis.
        :param upload_url: The URL used to upload files larger than 32MB to VirusTotal for analysis. Obtained from the `file_upload_url` method.
        :returns: A dictionary containing the resp_code and JSON response.
        """
        files = {"file": (basename(file), open(abspath(file), "rb"))}
        if self.API_VERSION == "v3":
            # If upload_url is provided, override default v3 API endpoint
            if upload_url:
                endpoint = upload_url
            else:
                # Use standard v3 API endpoint
                endpoint = f"{self.BASEURL}files"
            resp = self.make_request(endpoint, files=files, proxies=self.PROXIES)
        else:
            # v2 API request
            # If upload_url is provided, override default v2 API endpoint
            if upload_url:
                endpoint = upload_url
            else:
                # Use standard v2 API endpoint
                endpoint = f"{self.BASEURL}file/scan"
            params = {"apikey": self.API_KEY}
            resp = self.make_request(
                endpoint,
                params=params,
                files=files,
                proxies=self.PROXIES,
            )
        return resp

    def file_upload_url(self):
        """
        Get a URL for uploading files larger than 32MB to the VirusTotal API.

        NOTE: For the v2 API, this endpoint requires additional privileges. For the v3 API, no additional privileges are required based on the documentation.

        [v2 documentation](https://developers.virustotal.com/reference#file-scan-upload-url)

        [v3 documentation](https://developers.virustotal.com/v3.0/reference#files-upload-url)

        :returns: A dictionary containing the resp_code and JSON response.
        """
        if self.API_VERSION == "v3":
            resp = self.make_request(
                f"{self.BASE_URL}files/upload_url",
                method="GET",
                proxies=self.PROXIES,
            )
        else:
            # v2 API request
            params = {"apikey": self.API_KEY}
            resp = self.make_request(
                f"{self.BASE_URL}file/scan/upload_url",
                method="GET",
                proxies=self.PROXIES,
            )
        return resp

    def file_rescan(self, *resource: list):
        """
        Resend a file to VirusTotal for analysis. (https://developers.virustotal.com/v2.0/reference#file-rescan)
           :param *resource: A list of resource(s) of a specified file(s). Can be `md5/sha1/sha256 hashes`. Can be a combination of any of the three allowed hashes (MAX 25 items).
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        raise DeprecationWarning(
            "VirusTotal removed this API endpoint from the public API."
        )

    def file_report(self, *resource: list):
        """
        Retrieve scan report(s) for a given file from VirusTotal. (https://developers.virustotal.com/v2.0/reference#file-report)
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
        Send url(s) to VirusTotal. (https://developers.virustotal.com/v2.0/reference#url-scan)
           :param *url: A list of url(s) to be scanned. (MAX 4 per standard request rate).
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "url": "\n".join(*url)}
        resp = self.make_request(
            f"{self.BASEURL}url/scan", params=params, proxies=self.PROXIES
        )
        return resp

    def url_report(self, *resource: list, scan: int = None):
        """
        Retrieve scan report(s) for a given url(s) (https://developers.virustotal.com/v2.0/reference#url-report)
           :param *resource: A list of the url(s) and/or scan_id(s) report(s) to be retrieved (MAX 4 per standard request rate).
           :param scan: An optional parameter. When set to 1 it will automatically submit the URL for analysis if no report is found for it in VirusTotal's database.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "resource": "\n".join(*resource)}
        if scan is not None:
            params["scan"] = scan
        resp = self.make_request(
            f"{self.BASEURL}url/report", params=params, proxies=self.PROXIES
        )
        return resp

    def ipaddress_report(self, ip: str):
        """
        Retrieve a scan report for a specific ip address. (https://developers.virustotal.com/v2.0/reference#ip-address-report)
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

    def domain_report(self, domain: str):
        """
        Retrieve a scan report for a specific domain name. (https://developers.virustotal.com/v2.0/reference#domain-report)
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

    def put_comment(self, resource: str, comment: str):
        """
        Make comments on files and URLs. (https://developers.virustotal.com/v2.0/reference#comments-put)
           :param resource: The `md5/sha1/sha256 hash` of the file you want to review or the URL itself that you want to comment on.
           :param comment: The str comment to be submitted.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        params = {"apikey": self.API_KEY, "resource": resource, "comment": comment}
        resp = self.make_request(
            f"{self.BASEURL}comments/put", params=params, proxies=self.PROXIES
        )
        return resp

    def make_request(self, endpoint: str, params: dict, method="POST", **kwargs):
        """
        Helper function to make the request to the specified endpoint.
           :param endpoint: The specific VirusTotal API endpoint.
           :param method: The request method to use.
           :param params: The parameters to go along with the request.
           :rtype: A dictionary containing the resp_code and JSON response.
        """
        if method == "POST":
            resp = post(endpoint, params=params, headers=self.HEADERS, **kwargs)
        elif method == "GET":
            resp = get(endpoint, params=params, headers=self.HEADERS, **kwargs)
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
