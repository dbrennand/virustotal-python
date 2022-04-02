# Changelog

## 1.0.0

### Breaking Changes

* Changed default VirusTotal API to version 3.

* Dropped support for `COMPATIBILITY_ENABLED`

### Docs

* Updated README.

* Moved to Google docstring format.

* Refactored examples to favour VirusTotal API version 3.

### Tests

* Added new unit tests with 95% coverage.

### Misc Changes

* `API_VERSION` can now accept an `int` to specify VirusTotal API version to use.

* Added GitHub actions to automate testing and publishing.

## 0.2.0

Added `large_file` parameter to `request` so a file larger than 32MB can be submitted for analysis. See [#33](https://github.com/dbrennand/virustotal-python/pull/33). Thank you @smk762.

## 0.1.3

Update urllib3 to 1.26.5 to address [CVE-2021-33503](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33503).

## 0.1.2

Update dependencies for security vulnerability. Fixed an issue with some tests failing.

## 0.1.1

Added Context Manager support and tests. Updated dependencies and license year.

## 0.1.0

Added support for the VirusTotal v3 API. Library redesign (new usage, examples, tests and more.) See [#24](https://github.com/dbrennand/virustotal-python/pull/24).

## 0.0.9

Update dependencies for security vulnerability.

## 0.0.8

Updated dependencies, removed method `file_rescan`

## 0.0.7

Added tests. Updated dependencies, Updated examples and README, `url_report` param `scan` now accepts `type(int)`, no longer `type(str)`

## 0.0.6

Fixed usage example and dependencies in README.md, Setup github.io website, updated requirements.txt.

## 0.0.5

Added proxy support. Via HTTP(S) or using SOCKS: See [#8](https://github.com/dbrennand/virustotal-python/pull/8).

## 0.0.4

README.md updated; dependencies updated.

## 0.0.3

Updated dependencies for `urllib3` security vulnerability.

## 0.0.2

Changes to file_rescan(), file_report(), url_scan(), url_report() to improve ease of use of the wrapper. See issue [#2](https://github.com/dbrennand/virustotal-python/issues/2). Examples updated for changes.

## 0.0.1

Initial release of virustotal-python. Covered all endpoints of the Virustotal public API.
