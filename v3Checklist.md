# Add progress checklist for v3 API support

- [✔️] Bump `self.VERSION` to **0.1.0**.

- [✔️] Bump version to **0.1.0** in [setup.py](setup.py).

- [] Update project description in Github repository description.

- [✔️] Update project description in [README.md](README.md) and in [setup.py](setup.py).

- [✔️] Update changelog in [README.md](README.md).

- [✔️] Add `API_VERSION` parameter VirusTotal class `__init__` method.

- [✔️] Add v3 support for `file_scan`.

- [✔️] Add missing method `file_upload_url`.

- [] v3 API provides errors as [JSON response](https://developers.virustotal.com/v3.0/reference#errors). Accommodate this in `validate_response` helper function.

- [] Update examples in [examples.py](virustotal_python/examples.py) and [README.md](README.md).
