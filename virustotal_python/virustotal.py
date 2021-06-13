"""
MIT License

Copyright (c) 2021 dbrennand

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
from json.decoder import JSONDecodeError


class VirustotalError(Exception):
    """
    Class for VirusTotal API errors.
    """

    def __init__(self, response: requests.Response):
        """
        Initalisation for VirustotalError class.

        :param response: A requests.Response object from a failed API request to the VirusTotal API.
        """
        self.response = response

    def __str__(self):
        return f"Error {self.error().get('code', 'unknown')} ({self.response.status_code}): {self.error().get('message', 'No message')}"

    def error(self) -> dict:
        """
        Retrieve the error that occurred from a VirusTotal API request.

        [v3 documentation](https://developers.virustotal.com/v3.0/reference#errors)

        [v2 documentation](https://developers.virustotal.com/reference#api-responses)

        :returns: A dictionary containing the error code and message returned from the VirusTotal API (if any) otherwise, returns an empty dictionary.
        """
        # Attempt to decode JSON as the v3 VirusTotal API returns the error message as JSON
        try:
            return self.response.json().get("error", dict())
        except ValueError:
            # Catch exception if there is no JSON to be deserialized
            # Most likely using the v2 VirusTotal API
            # Check there is response text, if not, return an empty dict
            if self.response.text:
                return dict(message=self.response.text)
            else:
                return dict()


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
        Retrieve the HTTP headers of a VirusTotal API request.

        :returns: The HTTP headers of the requests.Response object.
        """
        return self.response.headers

    @property
    def status_code(self) -> int:
        """
        Retrieve the HTTP status code of a VirusTotal API request.

        :returns: The HTTP status code of the requests.Response object.
        """
        return self.response.status_code

    @property
    def text(self) -> str:
        """
        Retrieve the HTTP text response of a VirusTotal API request.

        :returns: The HTTP text response of the requests.Response object.
        """
        return self.response.text

    @property
    def requests_response(self) -> requests.Response:
        """
        Retrieve the HTTP requests.Response object of a VirusTotal API request.
        You may want to access this property if you wanted to read other aspects of the response such as cookies.

        :returns: A requests.Response object.
        """
        return self.response

    @property
    def links(self) -> Tuple[dict, None]:
        """
        Retrieve the value of the key 'links' in the JSON response from a VirusTotal API request.

        NOTE: Links are not retrieved for objects inside 'data'.

        [v3 documentation](https://developers.virustotal.com/v3.0/reference#collections)

        :returns: A dictionary containing the links used to retrieve the next set of objects (if any), otherwise, returns None.
        """
        return self.json().get("links", None)

    @property
    def meta(self) -> Tuple[dict, None]:
        """
        Retrieve the value of the key 'meta' in the JSON response from a VirusTotal API request.

        [v3 documentation](https://developers.virustotal.com/v3.0/reference#collections)

        :returns: A dictionary containing metadata about the object(s) (if any), otherwise, returns None.
        """
        return self.json().get("meta", None)

    @property
    def cursor(self) -> Tuple[str, None]:
        """
        Retrieve the value of the key 'cursor' in the JSON response value 'meta' from a VirusTotal API request.

        [v3 documentation](https://developers.virustotal.com/v3.0/reference#collections)

        :returns: A string representing the cursor used to retrieve additional related object(s), otherwise, returns None.
        """
        try:
            return self.meta.get("cursor", None)
        # Catch AttributeError that occurs when attemping to call attribute 'get' on None
        # which is returned if the 'meta' key is not present in the JSON response
        except AttributeError:
            return None

    @property
    def data(self) -> Tuple[dict, list, None]:
        """
        Retrieve the value of the key 'data' in the JSON response from a VirusTotal API request.

        [v3 documentation](https://developers.virustotal.com/v3.0/reference#objects)

        :returns: A dictionary or list depending on the number of objects returned from the VirusTotal API (if any) otherwise, returns None.
        """
        return self.json().get("data", None)

    @property
    def object_type(self) -> Tuple[list, str, None]:
        """
        Retrieve the object type(s) in the JSON response from a VirusTotal API request.

        [v3 documentation](https://developers.virustotal.com/v3.0/reference#objects)

        [More v3 documentation](https://developers.virustotal.com/v3.0/reference#collections)

        :returns: A list or string depending on the number of objects returned from the VirusTotal API (if any) otherwise, returns None.
        """
        data = self.data
        # Check if data is more than one object
        if isinstance(data, list):
            object_list = []
            for data_object in data:
                data_object_type = data_object.get("type", None)
                object_list.append(data_object_type)
            return object_list
        elif isinstance(data, dict):
            return data.get("type", None)
        else:
            return None

    @property
    def response_code(self) -> Tuple[int, None]:
        """
        Retrieve the value of the key 'response_code' in the JSON response from a VirusTotal v2 API request.

        [v2 documentation](https://developers.virustotal.com/reference#api-responses)

        :returns: An int of the response_code from the VirusTotal API (if any), otherwise, returns None.
        """
        return self.json().get("response_code", None)

    def json(self, **kwargs) -> Tuple[dict, list]:
        """
        Retrieve the JSON response of a VirusTotal API request.

        :param **kwargs: Parameters to pass to json. Identical to `json.loads(**kwargs)`.
        :returns: JSON response of the requests.Response object.
        :raises ValueError: Raises ValueError when the response body contains invalid JSON.
        """
        try:
            return self.response.json(**kwargs)
        except JSONDecodeError:
            return dict()


class Virustotal(object):
    """
    Interact with the public VirusTotal v2 and v3 APIs.

    [v2 documentation](https://www.virustotal.com/en/documentation/public-api/)

    [v3 documentation](https://developers.virustotal.com/v3.0/reference)
    """

    def __init__(
        self,
        API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", None),
        API_VERSION: str = "v2",
        COMPATIBILITY_ENABLED: bool = False,
        PROXIES: dict = None,
        TIMEOUT: float = None,
    ):
        """
        Initalisation function for the Virustotal class.

        :param API_KEY: The API key used to interact with the VirusTotal v2 and v3 APIs. Alternatively, the environment variable `VIRUSTOTAL_API_KEY` can be provided.
        :param API_VERSION: The version to use when interacting with the VirusTotal API. This parameter defaults to 'v2' for backwards compatibility.
        :param COMPATIBILITY_ENABLED: Preserve the old response format of virustotal-python versions prior to 0.1.0 for backwards compatibility.
        :param PROXIES: A dictionary containing proxies used when making requests.
        :param TIMEOUT: A float for the amount of time to wait in seconds for the HTTP request before timing out.
        :raises ValueError: Raises ValueError when no API_KEY is provided or the API_VERSION is invalid.
        """
        self.VERSION = "0.1.3"
        if API_KEY is None:
            raise ValueError(
                "An API key is required to interact with the VirusTotal API.\nProvide one to the API_KEY parameter or by setting the environment variable 'VIRUSTOTAL_API_KEY'."
            )
        self.API_KEY = API_KEY
        self.COMPATIBILITY_ENABLED = COMPATIBILITY_ENABLED
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
                f"The API version '{API_VERSION}' is not a valid VirusTotal API version.\nValid API versions are 'v2' or 'v3'."
            )

    # Context Manager support
    def __enter__(self):
        """
        Context Manager enter function.
        """
        return self

    def __exit__(self, type, value, traceback):
        """
        Context Manager exit function.
        """
        return

    def request(
        self,
        resource: str,
        params: dict = {},
        data: dict = None,
        json: dict = None,
        files: dict = None,
        method: str = "GET",
    ) -> Tuple[dict, VirustotalResponse]:
        """
        Make a request to the VirusTotal API.

        :param resource: A valid VirusTotal API endpoint. (E.g. 'files/{id}')
        :param params: A dictionary containing API endpoint query parameters.
        :param data: A dictionary containing the data to send in the body of the request.
        :param json: A dictionary containing the JSON payload to send with the request.
        :param files: A dictionary containing the file for multipart encoding upload. (E.g: {'file': ('filename', open('filename.txt', 'rb'))})
        :param method: The request method to use.
        :returns: A dictionary containing the HTTP response code (resp_code) and JSON response (json_resp) if self.COMPATIBILITY_ENABLED is True.
            Otherwise, a VirustotalResponse class object is returned. If a HTTP status not equal to 200 occurs. Then a VirustotalError class object is returned.
        :raises Exception: Raise Exception when an unsupported method is provided.
        """
        # Create API endpoint
        endpoint = f"{self.BASEURL}{resource}"
        # If API version being used is v2, add the API key to params
        if self.API_VERSION == "v2":
            params["apikey"] = self.API_KEY
        if method == "GET":
            response = requests.get(
                endpoint,
                params=params,
                data=data,
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
                data=data,
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
                data=data,
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
                data=data,
                json=json,
                files=files,
                headers=self.HEADERS,
                proxies=self.PROXIES,
                timeout=self.TIMEOUT,
            )
        else:
            raise Exception(f"The request method '{method}' is not supported.")
        # Validate response and return it
        return self.validate_response(response)

    def validate_response(
        self, response: requests.Response
    ) -> Tuple[dict, VirustotalResponse]:
        """
        Helper function to validate the request response.

        :param response: A requests.Response object for an API request made to the VirusTotal API.
        :returns: A dictionary containing the HTTP response code (resp_code) and JSON response (json_resp) if self.COMPATIBILITY_ENABLED is True otherwise, a VirustotalResponse class object is returned.
        :raises VirustotalError: Raises VirustotalError when an HTTP status code other than 200 (successfull) occurs.
        """
        if self.COMPATIBILITY_ENABLED:
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
            if response.status_code != 200:
                raise VirustotalError(response)
            else:
                return VirustotalResponse(response)
