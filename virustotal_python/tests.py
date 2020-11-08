import virustotal_python
import pytest
import os.path
from time import sleep
from base64 import urlsafe_b64encode


@pytest.fixture()
def vtotal_v3(request):
    yield virustotal_python.Virustotal(API_VERSION="v3")

    def fin():
        """
        Helper function which sleeps for 30 seconds between each test. This is to avoid VirusTotal 403 rate quota limits.
        """
        print("Sleeping for 30 seconds to avoid VirusTotal 403 rate quota limits...")
        sleep(30)

    request.addfinalizer(fin)


@pytest.fixture()
def vtotal_v2(request):
    yield virustotal_python.Virustotal()

    def fin():
        """
        Helper function which sleeps for 30 seconds between each test. This is to avoid VirusTotal 403 rate quota limits.
        """
        print("Sleeping for 30 seconds to avoid VirusTotal 403 rate quota limits...")
        sleep(30)

    request.addfinalizer(fin)


def test_file_scan_v3(vtotal_v3):
    """
    Test for sending a file to the VirusTotal v3 API for analysis.
    """
    # Create dictionary containing the file to send for multipart encoding upload
    files = {
        "file": (
            os.path.basename("virustotal_python/oldexamples.py"),
            open(os.path.abspath("virustotal_python/oldexamples.py"), "rb"),
        )
    }
    resp = vtotal_v3.request("files", files=files, method="POST")
    assert resp.status_code == 200
    assert resp.data


def test_file_scan_v2(vtotal_v2):
    """
    Test for sending a file to the VirusTotal v2 API for analysis.
    """
    # Create dictionary containing the file to send for multipart encoding upload
    files = {
        "file": (
            os.path.basename("virustotal_python/oldexamples.py"),
            open(os.path.abspath("virustotal_python/oldexamples.py"), "rb"),
        )
    }
    resp = vtotal_v2.request("file/scan", files=files, method="POST")
    assert resp.response_code == 1
