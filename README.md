# virustotal-python 🐍
![PyPI](https://img.shields.io/pypi/v/virustotal-python.svg?style=flat-square)

A Python library to interact with the public VirusTotal v2 and v3 APIs.

> [!NOTE]
>
> This library is intended to be used with the public VirusTotal APIs. However, it *could* be used to interact with premium API endpoints as well.

# Dependencies and installation

> [!NOTE]
>
> This library should work with Python versions >= 3.7.

```
[dev-packages]
black = "*"
twine = "*"
pytest = "*"

[packages]
requests = {extras = ["socks"],version = "*"}
```

Install `virustotal-python` using either:
* `pip3 install virustotal-python`, `pipenv install`, `pip3 install -r requirements.txt`, `python setup.py install`.

## Usage examples

> [!NOTE]
>
> See the [examples](examples) directory for several usage examples.
>
> Furthermore, check [`virustotal_python/virustotal.py`](virustotal_python/virustotal.py) for docstrings containing full parameter descriptions.

Authenticate using your VirusTotal API key:

> ![NOTE]
>
> To obtain a VirusTotal API key, [sign up](https://www.virustotal.com/gui/join-us) for a VirusTotal account.
>
> Then, view your VirusTotal API key.
>
> ![VirusTotal view API key](images/APIKey.png)

```python
from virustotal_python import Virustotal

# v3 example
vtotal = Virustotal(API_KEY="Insert API key here.", API_VERSION="v3")

# v2 example
vtotal = Virustotal(API_KEY="Insert API key here.")

# You can provide True to the `COMPATIBILITY_ENABLED` parameter to preserve the old response format of virustotal-python versions prior to 0.1.0
vtotal = Virustotal(API_KEY="Insert API key here.", API_VERSION="v3", COMPATIBILITY_ENABLED=True)

# You can also set proxies and timeouts for requests made by the library
vtotal = Virustotal(
    API_KEY="Insert API key here.",
    API_VERSION="v3",
    PROXIES={"http": "http://10.10.1.10:3128", "https": "http://10.10.1.10:1080"},
    TIMEOUT=5.0)
```

Additionally, it is possible to provide an API key via the environment variable `VIRUSTOTAL_API_KEY`.

Bash example:

```bash
export VIRUSTOTAL_API_KEY="Insert API key here."
```

PowerShell example:

```powershell
$Env:VIRUSTOTAL_API_KEY = "Insert API key here."
```

Now, initialise the `Virustotal` class:

```python
from virustotal_python import Virustotal

# v3 example
vtotal = Virustotal(API_VERSION="v3")

# v2 example
vtotal = Virustotal()
```

Send a file for analysis:

```python
import os.path
from pprint import pprint

# Declare PATH to file
FILE_PATH = "/path/to/file/to/scan.txt"

# Create dictionary containing the file to send for multipart encoding upload
files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}

# v3 example
resp = vtotal.request("files", files=files, method="POST")

# The v3 API returns the JSON response inside the 'data' key
# https://developers.virustotal.com/v3.0/reference#api-responses
# This property retrieves the structure inside 'data' from the JSON response
pprint(resp.data)
# Or if you provided COMPATIBILITY_ENABLED=True to the Virustotal class
pprint(resp["json_resp"])

# v2 example
resp = vtotal.request("file/scan", files=files, method="POST")

# The v2 API returns a response_code
# This property retrieves it from the JSON response
print(resp.response_code)
# Print JSON response from the API
pprint(resp.json())
```

Retrieve information about a file:

```python
from pprint import pprint

# The ID (either SHA-256, SHA-1 or MD5) identifying the file
FILE_ID = "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"

# v3 example
resp = vtotal.request(f"files/{FILE_ID}")

pprint(resp.data)

# v2 example
resp = vtotal.request("file/report", {"resource": FILE_ID})

print(resp.response_code)
pprint(resp.json())
```

Send a URL for analysis, retrieve the analysis report and catch any potential exceptions that may occur (Non 200 HTTP status codes):

```python
from virustotal_python import VirustotalError
from pprint import pprint
from base64 import urlsafe_b64encode

url = "ihaveaproblem.info"

# v3 example
try:
    # Send URL to VirusTotal for analysis
    resp = vtotal.request("urls", data={"url": url}, method="POST")
    # URL safe encode URL in base64 format
    # https://developers.virustotal.com/v3.0/reference#url
    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
    # Obtain the analysis results for the URL using the url_id
    analysis_resp = vtotal.request(f"urls/{url_id}")
    pprint(analysis_resp.object_type)
    pprint(analysis_resp.data)
except VirustotalError as err:
    print(f"An error occurred: {err}\nCatching and continuing with program.")

# v2 example
try:
    # Send a URL to VirusTotal for analysis
    resp = vtotal.request("url/scan", params={"url": url}, method="POST")
    url_resp = resp.json()
    # Obtain scan_id
    scan_id = url_resp["scan_id"]
    # Request report for URL analysis
    analysis_resp = vtotal.request("url/report", params={"resource": scan_id})
    print(analysis_resp.response_code)
    pprint(analysis_resp.json())
except VirustotalError as err:
    print(f"An error occurred: {err}\nCatching and continuing with program.")
```

Retrieve information about a domain:

```python
from pprint import pprint

domain = "virustotal.com"

# v3 example
resp = vtotal.request(f"domains/{domain}")

pprint(resp.data)

# v2 example
resp = vtotal.request("domain/report", params={"domain": domain})

print(resp.response_code)
pprint(resp.json())
```

## Running the tests

To run the tests, perform the following steps:

1. Ensure pytest is installed using: `pip install pytest`

2. Export your API key to the environment variable `VIRUSTOTAL_API_KEY` (instructions above).

3. From the root directory of the project run `pytest -s .\virustotal_python\tests.py`

## Changelog

* 0.1.0 - Added support for the VirusTotal v3 API. Changed the library considerably (new usage, examples, tests and more.)

* 0.0.9 - Update dependencies for security vulnerability.

* 0.0.8 - Updated dependencies, removed method `file_rescan`

* 0.0.7 - Added tests. Updated dependencies, Updated examples and README, `url_report` param `scan` now accepts `type(int)`, **no** longer `type(str)`

* 0.0.6 - Fixed usage example and dependencies in README.md, Setup github.io website, updated requirements.txt.

* 0.0.5 - Added Proxy support. Via HTTP(S) or using SOCKS: See [#8](https://github.com/dbrennand/virustotal-python/pull/8).

* 0.0.4 - README.md updated; dependencies updated.

* 0.0.3 - Updated dependencies for urllib3 security vulnerability.

* 0.0.2 - Changes to file_rescan(), file_report(), url_scan(), url_report() to improve ease of use of the wrapper. See issue [#2](https://github.com/dbrennand/virustotal-python/issues/2). Examples updated for changes.

* 0.0.1 - Initial release of virustotal-python. Covered all endpoints of the Virustotal public API.

## Authors -- Contributors

* **dbrennand** - *Author* - [dbrennand](https://github.com/dbrennand)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) for details.
