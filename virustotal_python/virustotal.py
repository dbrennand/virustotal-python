"""
MIT License

Copyright (c) 2023 dbrennand

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
from typing import Union
from json.decoder import JSONDecodeError


class VirustotalError(Exception):
    """Class for VirusTotal API errors."""

    def __init__(self, response: requests.Response) -> None:
        """Initialisation for `VirustotalError`.

        Args:
            response (requests.Response): From a failed API request to the VirusTotal API.
        """
        self.response = response

    def __str__(self) -> str:
        """String dunder method for `VirustotalError`.

        Returns:
            str: Containing the error code, HTTP status code and error message from a failed VirusTotal API request.
        """
        error = self.error()
        return f"Error {error.get('code', 'Unknown')} ({self.response.status_code}): {error.get('message', 'No message')}"

    def error(self) -> dict:
        """Retrieve the error that occurred from a failed VirusTotal API request.

        https://developers.virustotal.com/v2.0/reference/api-responses

        https://developers.virustotal.com/reference/errors

        Returns:
            dict: Containing the error code and message returned from the VirusTotal API (if any) otherwise, returns an empty dictionary.
        """
        # Attempt to decode JSON as the v3 VirusTotal API returns the error message as JSON
        # Fallback to an empty dict if error is somehow missing
        try:
            return self.response.json().get("error", dict())
        except ValueError:
            # Catch ValueError if JSON fails to be deserialized or there is no JSON
            # Most likely using the v2 VirusTotal API
            # Check there is response text, if not, return an empty dict
            if self.response.text:
                return dict(message=self.response.text)
            else:
                return dict()


class VirustotalResponse(object):
    """Response class for VirusTotal API requests."""

    def __init__(self, response: requests.Response):
        """Initialisation for `VirustotalResponse`.

        Args:
            response (requests.Response): From a successful API request to the VirusTotal API.
        """
        self.response = response

    @property
    def headers(self) -> dict:
        """Retrieve the HTTP headers of a VirusTotal API request.

        Returns:
            dict: The HTTP headers of the requests.Response object.
        """
        return self.response.headers

    @property
    def status_code(self) -> int:
        """Retrieve the HTTP status code of a VirusTotal API request.

        Returns:
            int: The HTTP status code of the requests.Response object.
        """
        return self.response.status_code

    @property
    def text(self) -> str:
        """Retrieve the HTTP text response of a VirusTotal API request.

        Returns:
            str: The HTTP text response of the requests.Response object.
        """
        return self.response.text

    @property
    def requests_response(self) -> requests.Response:
        """Retrieve the `requests.Response` object of a VirusTotal API request.
        You may want to access this property if you wanted to read other aspects of the response such as cookies.

        Returns:
            requests.Response: From a successful API request to the VirusTotal API.
        """
        return self.response

    @property
    def links(self) -> Union[dict, None]:
        """Retrieve the value of the key 'links' in the JSON response from a VirusTotal API request.

        https://developers.virustotal.com/reference/collections

        NOTE: Links are not retrieved for objects inside 'data'.

        Returns:
            Union[dict, None]: The links used to retrieve the next set of objects (if any), otherwise, returns `None`.
        """
        return self.json().get("links", None)

    @property
    def meta(self) -> Union[dict, None]:
        """Retrieve the value of the key 'meta' in the JSON response from a VirusTotal API request.

        https://developers.virustotal.com/reference/collections

        Returns:
            Union[dict, None]: The metadata about the object(s) (if any), otherwise, returns `None`.
        """
        return self.json().get("meta", None)

    @property
    def cursor(self) -> Union[str, None]:
        """Retrieve the value of the key 'cursor' in the JSON response value 'meta' from a VirusTotal API request.

        https://developers.virustotal.com/reference/collections

        Returns:
            Union[str, None]: The cursor used to retrieve related object(s), otherwise, returns `None`.
        """
        try:
            return self.meta.get("cursor", None)
        # Catch AttributeError that occurs when attempting to call attribute 'get' on None
        # which is raised if the 'meta' key is not present in the JSON response
        except AttributeError:
            return None

    @property
    def data(self) -> Union[dict, list, str, None]:
        """Retrieve the value of the key 'data' in the JSON response from a VirusTotal API request.

        https://developers.virustotal.com/reference/objects

        Returns:
            Union[dict, list, str, None]: The data from a VirusTotal API request (if any) otherwise, returns `None`.
        """
        return self.json().get("data", None)

    @property
    def object_type(self) -> Union[list, str, None]:
        """Retrieve the object type(s) in the JSON response from a VirusTotal API request.

        https://developers.virustotal.com/reference/objects

        https://developers.virustotal.com/reference/collections

        Returns:
            Union[list, str, None]: A list or string depending on the number of objects returned (if any) otherwise, returns `None`.
        """
        data = self.data
        # Check if data contains more than one object
        if isinstance(data, list):
            object_list = []
            for data_object in data:
                data_object_type = data_object.get("type", None)
                object_list.append(data_object_type)
            return object_list
        # Data contains only one object
        elif isinstance(data, dict):
            return data.get("type", None)
        else:
            return None

    @property
    def response_code(self) -> Union[int, None]:
        """Retrieve the value of the key 'response_code' in the JSON response from a VirusTotal v2 API request.

        https://developers.virustotal.com/v2.0/reference/api-responses

        Returns:
            Union[int, None]: The response_code from the VirusTotal API (if any), otherwise, returns `None`.
        """
        return self.json().get("response_code", None)

    def json(self, **kwargs) -> dict:
        """Retrieve the JSON response from a VirusTotal API request.

        Args:
            **kwargs: Identical to `json.loads(**kwargs)`.

        Returns:
            dict: JSON response from a VirusTotal API request.
        """
        try:
            return self.response.json(**kwargs)
        except JSONDecodeError:
            return dict()


class Virustotal(object):
    """Interact with the public VirusTotal v3 and v2 APIs.

    https://developers.virustotal.com/v3.0/reference

    https://developers.virustotal.com/v2.0/reference
    """

    def __init__(
        self,
        API_KEY: str = None,
        API_VERSION: Union[int, str] = 3,
        PROXIES: dict = None,
        TIMEOUT: float = None,
    ):
        """Interact with the public VirusTotal v3 and v2 APIs.

        Args:
            API_KEY (str, optional): The API key used to interact with the VirusTotal v3 and v2 APIs.
                Alternatively, the environment variable `VIRUSTOTAL_API_KEY` can be provided.
            API_VERSION (Union[int, str], optional): The version to use when interacting with the VirusTotal API.
                Defaults to 3.
            PROXIES (dict, optional): Proxies to use when making requests.
                E.g. `{"http": "http://10.10.1.10:3128", "https": "https://10.10.1.10:1080"}`
                Defaults to `None`.
            TIMEOUT (float, optional): The amount of time (in seconds) to wait for the HTTP request before timing out.
                Defaults to `None`.

        Raises:
            ValueError: When no `API_KEY` is provided or the `API_VERSION` is invalid.
        """
        if API_KEY is None:
            API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", None)
            if API_KEY is None:
                raise ValueError(
                    "An API key is required to interact with the VirusTotal API.\nProvide one to the API_KEY parameter or by setting the environment variable 'VIRUSTOTAL_API_KEY'."
                )
        self.API_KEY = API_KEY
        self.PROXIES = PROXIES
        self.TIMEOUT = TIMEOUT
        # Declare appropriate variables depending on the API_VERSION provided
        if (API_VERSION == "v2") or (API_VERSION == 2):
            self.API_VERSION = API_VERSION
            self.BASEURL = "https://www.virustotal.com/vtapi/v2/"
            self.HEADERS = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": f"gzip, virustotal-python 1.0.2",
            }
        elif (API_VERSION == "v3") or (API_VERSION == 3):
            self.API_VERSION = API_VERSION
            self.BASEURL = "https://www.virustotal.com/api/v3/"
            self.HEADERS = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": f"gzip, virustotal-python 1.0.2",
                "x-apikey": f"{self.API_KEY}",
            }
        else:
            raise ValueError(
                f"The API version '{API_VERSION}' is not a valid VirusTotal API version.\nValid API versions are 'v2', 2, 'v3' and 3."
            )

    def __enter__(self):
        """Context Manager enter function."""
        return self

    def __exit__(self, type, value, traceback):
        """Context Manager exit function."""
        return

    def request(
        self,
        resource: str,
        params: dict = {},
        data: dict = None,
        json: dict = None,
        files: dict = None,
        method: str = "GET",
        large_file: bool = False,
    ) -> VirustotalResponse:
        """Make a request to the VirusTotal API.

        Args:
            resource (str): A valid VirusTotal API endpoint. E.g. `f'files/{id}'`.
            params (dict, optional): API endpoint query parameters. Defaults to `{}`.
            data (dict, optional): Data to send in the body of the request. Defaults to `None`.
            json (dict, optional): JSON payload to send with the request. Defaults to `None`.
            files (dict, optional): File(s) for multipart encoding upload. Defaults to `None`.
            method (str, optional): The HTTP request method to use. Defaults to `"GET"`.
            large_file (bool, optional): If a file is larger than 32MB, a custom generated upload URL is required.
                If this param is set to `True`, this URL can be set via the resource param. Defaults to `False`.

        Raises:
            NotImplementedError: When a unsupported HTTP method is provided.
            VirustotalError: When a failed VirusTotal API response occurs.

        Returns:
            VirustotalResponse: A `VirustotalResponse` class object.
        """
        endpoint = f"{self.BASEURL}{resource}"
        if large_file:
            endpoint = resource
        # VirusTotal API version 2 requires API_KEY to be in the request parameters
        if (self.API_VERSION == "v2") or (self.API_VERSION == 2):
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
            raise NotImplementedError(
                f"The request method '{method}' is not implemented."
            )
        if response.status_code != 200:
            raise VirustotalError(response)
        else:
            return VirustotalResponse(response)
