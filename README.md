# virustotal-python 🐍
![PyPI](https://img.shields.io/pypi/v/virustotal-python.svg?style=flat-square)

A light wrapper around the public VirusTotal v2 and v3 API.

> [!NOTE]
> This library supports the public VirusTotal APIs. However, it *could* be used to interact with premium API endpoints as well.

# Dependencies and installation

> [!NOTE]
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

## Example usage (WIP)

> [!NOTE]
> See the [examples](examples) directory for several usage examples.
> Furthermore, check `virustotal_python/virustotal.py` for docstrings containing full parameter descriptions.

### Authenticate

```python
from virustotal_python import Virustotal
from pprint import pprint

# v3
vtotal = Virustotal(API_KEY="Insert API key here.", API_VERSION="v3")

# v2
vtotal = Virustotal(API_KEY="Insert API key here.")

# You can provide True to the `COMPATIBILITY_ENABLED` parameter to preserve the old response format of previous virustotal-python versions prior to 0.1.0
vtotal = Virustotal(API_KEY="Insert API key here.", API_VERSION="v3", COMPATIBILITY_ENABLED=True)
```

## Changelog

* 0.1.0 - Added support for the VirusTotal v3 API. Changed the library considerably (new usage, tests etc).

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
