# virustotal-python 🐍
![PyPI](https://img.shields.io/pypi/v/virustotal-python.svg?style=flat-square)

A light wrapper around the public VirusTotal API.

# Dependancies
* Written in Python 3.7. Python 2 is **not** supported; sorry 😢.

```
[dev-packages]
black = "*"
twine = "*"

[packages]
requests = {extras = ["socks"],version = "*"}
```

```pipenv install```

Or 

```pip3 install -r requirements.txt```

Or

```pip3 install virustotal-python```

## Example Usage
```python
from virustotal_python import Virustotal
from pprint import pprint

# Normal Initialisation.
vtotal = Virustotal("Insert API Key Here.")

# NEW as of version 0.0.5: Proxy support.
# Example Usage: Using HTTP(S)
vtotal = Virustotal(
    "Insert API Key Here.",
    {"http": "http://10.10.1.10:3128", "https": "http://10.10.1.10:1080"})
# Or using SOCKS
vtotal = Virustotal(
    "Insert API Key Here.",
    {"http": "socks5://user:pass@host:port", "https": "socks5://user:pass@host:port"})

# NOTE: Check virustotal.py for docstrings containing full parameter descriptions.

# Send a file to Virustotal for analysis.
resp = vtotal.file_scan("./test.py")  # PATH to file for querying.

# Resend a file to Virustotal for analysis.
# A list containing the resource (SHA256) HASH of the file above.
resp = vtotal.file_rescan(
    ["75efd85cf6f8a962fe016787a7f57206ea9263086ee496fc62e3fc56734d4b53"]
)
# A list containing md5/sha1/sha256 hashes. Can be a combination of any of the three allowed hashes (MAX 25 items).
# NOTE: The second hash here is flagged as malicious by multiple engines.
resp = vtotal.file_rescan(
    [
        "75efd85cf6f8a962fe016787a7f57206ea9263086ee496fc62e3fc56734d4b53",
        "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115",
    ]
)

# Retrieve scan report(s) for given file(s) from Virustotal.
# A list containing the resource (SHA256) HASH of a known malicious file.
resp = vtotal.file_report(
    ["9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"]
)
# A list of resource(s). Can be `md5/sha1/sha256 hashes` and/or combination of hashes and scan_ids (MAX 4 per standard request rate).
# The first is a scan_id, the second is a SHA256 HASH.
resp = vtotal.file_report(
    [
        "75efd85cf6f8a962fe016787a7f57206ea9263086ee496fc62e3fc56734d4b53-1555351539",
        "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115",
    ]
)

# Query url(s) to VirusTotal.
# A list containing a url to be scanned by VirusTotal.
resp = vtotal.url_scan(["ihaveaproblem.info"])  # Query a single url.
# A list of url(s) to be scanned by VirusTotal (MAX 4 per standard request rate).
resp = vtotal.url_scan(
    ["ihaveaproblem.info", "google.com", "wikipedia.com", "github.com"]
)

# Retrieve url report(s)
# A list containing the url of the report to be retrieved.
resp = vtotal.url_report(["ihaveaproblem.info"])  # Query a single url.
# A list of the url(s) and/or scan_id(s) report(s) to be retrieved (MAX 4 per standard request rate).
# The first object in the list is a scan_id.
resp = vtotal.url_report(
    [
        "fd21590d9df715452c8c000e1b5aa909c7c5ea434c2ddcad3f4ccfe9b0ee224e-1555352750",
        "google.com",
        "wikipedia.com",
        "github.com",
    ],
    scan="1",
)

# Query an IP to Virustotal.
resp = vtotal.ipaddress_report("90.156.201.27")

# Retrieve a domain report.
resp = vtotal.domain_report("027.ru")

# Put a comment onto a specific resource.
resp = vtotal.put_comment(
    "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115",
    comment="#watchout, this looks very malicious!",
)

pprint(resp)
```

```python
# Example resp for url_scan().
# Assuming you have already initiated Virustotal() and imported pprint.
resp = vtotal.url_scan(["ihaveaproblem.info"]) # Query a single url.
pprint(resp)
{'json_resp': {'permalink': 'https://www.virustotal.com/url/fd21590d9df715452c8c000e1b5aa909c7c5ea434c2ddcad3f4ccfe9b0ee224e/analysis/1549973453/',
               'resource': 'http://ihaveaproblem.info/',
               'response_code': 1,
               'scan_date': '2019-02-12 12:10:53',
               'scan_id': 'fd21590d9df715452c8c000e1b5aa909c7c5ea434c2ddcad3f4ccfe9b0ee224e-1549973453',
               'url': 'http://ihaveaproblem.info/',
               'verbose_msg': 'Scan request successfully queued, come back '
                              'later for the report'},
 'status_code': 200}
```

## Changelog

* 0.0.6 - Fixed usage example and dependencies in README.md, Setup github.io website, updated requirements.txt.

* 0.0.5 - Added Proxy support. Via HTTP(S) or using SOCKS: See [#8](https://github.com/Dextroz/virustotal-python/pull/8).

* 0.0.4 - README.md updated; dependencies updated.

* 0.0.3 - Updated dependencies for urllib3 security vulnerability.

* 0.0.2 - Changes to file_rescan(), file_report(), url_scan(), url_report() to improve ease of use of the wrapper. See issue [#2](https://github.com/Dextroz/virustotal-python/issues/2). Examples updated for changes.

* 0.0.1 - Inital release of virustotal-python. Covered all endpoints of the Virustotal public API. 

## Authors -- Contributors

* **Dextroz** - *Author* - [Dextroz](https://github.com/Dextroz)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) for details.