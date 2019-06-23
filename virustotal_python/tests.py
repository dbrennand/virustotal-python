from virustotal_python import Virustotal
from time import sleep
import pytest


@pytest.fixture
def virustotal_object(request):
    API_KEY = "Insert API Key Here."
    yield Virustotal(API_KEY)

    def fin():
        """
        Sleep for 30 seconds after each test; to avoid Virustotal 403 rate quota limit.
        """
        print("Sleeping for 30 seconds...")
        sleep(30)

    request.addfinalizer(fin)


def assert_content(resp):
    """
    Check json_resp data which is nested.
        :param content: The nested json_resp object.
    """
    for content in enumerate(resp["json_resp"]):
        assert content[1]["response_code"] == 1


def test_file_scan(virustotal_object):
    resp = virustotal_object.file_scan("./examples.py")
    assert resp["status_code"] == 200
    assert resp["json_resp"]["response_code"] == 1


def test_file_rescan(virustotal_object):
    resp = virustotal_object.file_rescan(
        [
            "75efd85cf6f8a962fe016787a7f57206ea9263086ee496fc62e3fc56734d4b53",
            "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115",
        ]
    )
    assert resp["status_code"] == 200
    assert_content(resp)


def test_file_report(virustotal_object):
    resp = virustotal_object.file_report(
        [
            "75efd85cf6f8a962fe016787a7f57206ea9263086ee496fc62e3fc56734d4b53-1555351539",
            "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115",
        ]
    )
    assert resp["status_code"] == 200
    assert_content(resp)


def test_url_scan(virustotal_object):
    resp = virustotal_object.url_scan(
        ["ihaveaproblem.info", "google.com", "wikipedia.com", "github.com"]
    )
    assert resp["status_code"] == 200
    assert_content(resp)


def test_url_report(virustotal_object):
    resp = virustotal_object.url_report(["ihaveaproblem.info"], scan=1)
    assert resp["status_code"] == 200
    assert resp["json_resp"]["response_code"] == 1


def test_ipaddress_report(virustotal_object):
    resp = virustotal_object.ipaddress_report("90.156.201.27")
    assert resp["status_code"] == 200
    assert resp["json_resp"]["response_code"] == 1


def test_domain_report(virustotal_object):
    resp = virustotal_object.domain_report("027.ru")
    assert resp["status_code"] == 200
    assert resp["json_resp"]["response_code"] == 1
