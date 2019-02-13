# virustotal-python
A light wrapper around the public VirusTotal API.

# Dependancies
* Written in Python 3.7. Python 2 is **not** supported; sorry 😢.

```
[dev-packages]
black = "*"

[packages]
requests = "*"
```

```pipenv install```

Or

```pip3 install virustotal-python```

## Example Usage
```python
from virustotal_python import Virustotal
from pprint import pprint
vtotal = Virustotal("Insert API Key Here.")

# NOTE: Check virustotal.py for docstrings containing full parameter descriptions.

# Send a file to Virustotal for analysis.
resp = vtotal.file_scan("./test.py") # PATH to file for querying.

# Resend a file to Virustotal for analysis.
# Contains the resource (SHA256) HASH of the file above.
resp = vtotal.file_rescan("75efd85cf6f8a962fe016787a7f57206ea9263086ee496fc62e3fc56734d4b53")
# Also accepts a CSV list (MAX 25 items)
resp = vtotal.file_rescan("HASH,HASH,HASH,HASH,etc.")

# Retrieve scan report(s) for a given file from Virustotal. 
resp = vtotal.file_report("75efd85cf6f8a962fe016787a7f57206ea9263086ee496fc62e3fc56734d4b53")
# Or accepts a CSV list with a combination of scan_ids and HASHs.
resp = vtotal.file_report("scan_id,HASH,scan_id,HASH")

# Query url(s) to VirusTotal.
resp = vtotal.url_scan("ihaveaproblem.info") # Query a single url.
resp = vtotal.url_scan("ihaveaproblem.info\ngoogle.com\nwikipedia.com\ngithub.com") # Query multiple url(s) seperated by "\n" character.

# Retrieve report(s)
resp = vtotal.url_report("ihaveaproblem.info") # Query a single url.
resp = vtotal.url_report("ihaveaproblem.info\ngoogle.com\nwikipedia.com\ngithub.com", scan="1") # Get the report(s) for a url(s), scan_id(s).

# Query an IP to Virustotal.
resp = vtotal.ipaddress_report("90.156.201.27")

# Retrieve a domain report.
resp = vtotal.domain_report("027.ru")

# Put a comment onto a specific resource.
resp = vtotal.put_comment("ihaveaproblem.info", comment="This website is flagged by a few scanners as malicious! #watchout")
```

```python
# Example resp for url_scan().
# Assuming you have already initiated Virustotal() and imported pprint.
resp = vtotal.url_scan("ihaveaproblem.info") # Query a single url.
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

## Authors -- Contributors

* **Dextroz** - *Author* - [Dextroz](https://github.com/Dextroz)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) for details.