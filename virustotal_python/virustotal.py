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
import requests
import os
from typing import Tuple


class VirustotalResponse(object):
    """
    Response class for VirusTotal API requests.
    """

    def __init__(self, response: requests.Response):
        """
        Initalisation for VirustotalResponse class.

        :param response: A requests.Response object from a successfull API request to the VirusTotal API.
        """
        self.response = response

    @property
    def headers(self) -> dict:
        """
        Obtain the HTTP headers of a VirusTotal API request.

        :returns: The HTTP headers of the requests.Response object.
        """
        return self.response.headers

    @property
    def status_code(self) -> int:
        """
        Obtain the HTTP status code of a VirusTotal API request.

        :returns: The HTTP status code of the requests.Response object.
        """
        return self.response.status_code

    @property
    def text(self) -> str:
        """
        Obtain the HTTP text response of a VirusTotal API request.

        :returns: The HTTP text response of the requests.Response object.
        """
        return self.response.text

    def response(self) -> requests.Response:
        """
        Obtain the HTTP response object (requests.Response) of a VirusTotal API request.
        You may want to access this property if you wanted to read other aspects of the response such as cookies.

        :returns: A requests.Response object.
        """
        return self.response

    def json(self, **kwargs) -> dict:
        """
        Obtain the JSON response of a VirusTotal API request.

        :param **kwargs: Parameters to pass to json. Identical to `json.loads(**kwargs)`.
        :returns: JSON response of the requests.Response object.
        :raises ValueError: Raises ValueError when there is no JSON in the response body to deserialize.
        """
        return self.response.json(**kwargs)

    def response_code(self) -> Tuple[int, None]:
        """
        Obtain the response_code from the JSON response of a VirusTotal API request.

        [v2 documentation](https://developers.virustotal.com/reference#api-responses)

        :returns: An int of the response_code from the VirusTotal API JSON response (if any), otherwise, returns None.
        """
        if self.status_code == 200:
            json_resp = self.json()
            # response_code will only be present in a v2 VirusTotal request
            # Check for it and if present, return it
            response_code = json_resp.get("response_code", None)
            if response_code:
                return response_code
            else:
                return None
        else:
            return None

    def error(self) -> Tuple[dict, None]:
        """
        Obtain the error that occurred from a VirusTotal API request (if any).

        [v3 documentation](https://developers.virustotal.com/v3.0/reference#errors)

        [v2 documentation](https://developers.virustotal.com/reference#api-responses)

        :returns: A dictionary containing the error code and message returned from the VirusTotal API (if any) otherwise, returns None.
        """
        if self.status_code != 200:
            # Attempt to decode JSON as the v3 VirusTotal API returns the error message as JSON
            try:
                return self.json().get("error", None)
            except ValueError:
                # Catch exception if there is no JSON to be deserialized
                # Most likely using the v2 VirusTotal API
                # Fallback to standard dict object containing the HTTP response text
                return dict(error=self.text)
        else:
            return None


class Virustotal(object):
    """
    Interact with the public VirusTotal API.

    [v2 documentation](https://www.virustotal.com/en/documentation/public-api/)

    [v3 documentation](https://developers.virustotal.com/v3.0/reference)
    """

    def __init__(
        self,
        API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", None),
        API_VERSION: str = "v2",
        PROXIES: dict = None,
        TIMEOUT: float = None,
    ):
        """
        Initalisation function for Virustotal class.

        :param API_KEY: The API key used to interact with the VirusTotal v2 and v3 APIs. Alternatively, the environment variable `VIRUSTOTAL_API_KEY` can be provided.
        :param API_VERSION: The version to use when interacting with the VirusTotal API. This parameter defaults to 'v2' for backwards compatibility.
        :param PROXIES: A dictionary containing proxies used when making requests.
        :param TIMEOUT: A float for the amount of time to wait in seconds for the HTTP request before timing out.
        :raises ValueError: Raises ValueError when no API_KEY is provided or the API_VERSION is invalid.
        """
        self.VERSION = "0.1.0"
        if API_KEY is None:
            raise ValueError(
                "An API key is required to interact with the VirusTotal API.\nProvide one to the API_KEY parameter or by setting the environment variable VIRUSTOTAL_API_KEY."
            )
        self.API_KEY = API_KEY
        self.PROXIES = PROXIES
        self.TIMEOUT = TIMEOUT
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
                f"The API version '{API_VERSION}' is not a valid VirusTotal API version.\nValid API versions are: 'v2' or 'v3'."
            )

    def request(
        self,
        resource: str,
        params: dict = None,
        method: str = "GET",
        json: dict = None,
        files: dict = None,
        backwards_compatibility: bool = False,
    ) -> Tuple[dict, VirustotalResponse]:
        """
        Make a request to the VirusTotal API.

        :param resource: A valid VirusTotal API endpoint. (E.g. 'files/{id}')
        :param params: A dictionary containing API endpoint parameters.
        :param method: The request method to use.
        :param json: A dictionary containing the JSON payload to send.
        :param files: A dictionary containing the file for multipart encoding upload. (E.g: {'file': ('filename', open('filename.txt', 'rb'))})
        :param backwards_compatibility: Preserve the old response format of previous virustotal-python versions prior to 0.1.0.
        :returns: A dictionary containing the HTTP response code (resp_code) and JSON response (json_resp) if backwards_compatibility is True otherwise, a VirustotalResponse class object is returned.
        :raises Exception: Raise Exception when an unsupported method is provided.
        """
        # Create API endpoint
        endpoint = f"{self.BASE_URL}{resource}"
        if method == "GET":
            response = requests.get(
                endpoint,
                params=params,
                json=json,
                files=files,
                headers=self.HEADERS,
                proxies=self.PROXIES,
                timeout=self.TIMEOUT,
            )
        elif method == "POST":
            response = requests.post(
                endpoint,
                params=params,
                json=json,
                files=files,
                headers=self.HEADERS,
                proxies=self.PROXIES,
                timeout=self.TIMEOUT,
            )
        elif method == "PATCH":
            response = requests.patch(
                endpoint,
                params=params,
                json=json,
                files=files,
                headers=self.HEADERS,
                proxies=self.PROXIES,
                timeout=self.TIMEOUT,
            )
        elif method == "DELETE":
            response = requests.delete(
                endpoint,
                params=params,
                json=json,
                files=files,
                headers=self.HEADERS,
                proxies=self.PROXIES,
                timeout=self.TIMEOUT,
            )
        else:
            raise Exception(f"The request method '{method}' is not supported.")
        # Validate response and return it
        return self.validate_response(
            response, backwards_compatibility=backwards_compatibility
        )

    def validate_response(
        self, response: requests.Response, backwards_compatibility: bool = False
    ) -> Tuple[dict, VirustotalResponse]:
        """
        Helper function to validate the request response.

        :param response: A requests.Response object from a successfull API request to the VirusTotal API.
        :param backwards_compatibility: Preserve the old response format of previous virustotal-python versions prior to 0.1.0.
        :returns: A dictionary containing the resp_code and JSON response (if any) or VirustotalResponse class object.
        """
        if backwards_compatibility:
            if response.status_code == 200:
                json_resp = response.json()
                return dict(status_code=response.status_code, json_resp=json_resp)
            else:
                # An error has occurred
                # The v3 API returns the error as JSON, attempt to retrieve it
                try:
                    error_json = response.json()
                except ValueError:
                    # API version being used is likely to be v2. Catch the raised ValueError and continue
                    pass
                return dict(
                    status_code=response.status_code,
                    # Provide JSON error message if retrieved successfully, otherwise fallback on response.text
                    error=(error_json if error_json else response.text),
                    resp=response.content,
                )
        else:
            return VirustotalResponse(response)
