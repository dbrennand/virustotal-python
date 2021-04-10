import virustotal_python
import pytest
import os.path
from time import sleep
from base64 import urlsafe_b64encode

# Declare variables for tests
# Create dictionary containing the file to send for multipart encoding upload
FILES = {
    "file": (
        os.path.basename("virustotal_python/oldexamples.py"),
        open(os.path.abspath("virustotal_python/oldexamples.py"), "rb"),
    )
}
# The ID (either SHA-256, SHA-1 or MD5) identifying the file
FILE_ID = "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"
# Example IP address (Google DNS)
IP = "8.8.8.8"
# Example ID of a graph
## NOTE: There are no comments on this graph so an empty list is returned
GRAPH_ID = "g70fae134aefc4e2f90f069aba47d15a92e0073564310443aa0b6ca3384f5240d"
# URL/domain identifier
URL_DOMAIN = "google.com"
# Example comment ID
COMMENT_ID = "f-9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115-07457619"


@pytest.fixture()
def vtotal_v2(request):
    yield virustotal_python.Virustotal()

    def fin():
        """
        Helper function which sleeps for 15 seconds between each test. This is to avoid VirusTotal 403 rate quota limits.
        """
        print("Sleeping for 15 seconds to avoid VirusTotal 403 rate quota limits...")
        sleep(15)

    request.addfinalizer(fin)


@pytest.fixture()
def vtotal_v3(request):
    yield virustotal_python.Virustotal(API_VERSION="v3")

    def fin():
        """
        Helper function which sleeps for 15 seconds between each test. This is to avoid VirusTotal 403 rate quota limits.
        """
        print("Sleeping for 15 seconds to avoid VirusTotal 403 rate quota limits...")
        sleep(15)

    request.addfinalizer(fin)


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
    resp = vtotal_v2.request("file/scan", files=FILES, method="POST")
    data = resp.json()
    assert resp.response_code == 1
    assert data["scan_id"]
    assert data["permalink"]


def test_file_scan_v3(vtotal_v3):
    """
    Test for sending a file to the VirusTotal v3 API for analysis.
    """
    resp = vtotal_v3.request("files", files=FILES, method="POST")
    assert resp.status_code == 200
    data = resp.data
    assert data["id"]
    assert data["type"] == "analysis"


def test_file_info_v2(vtotal_v2):
    """
    Test for retrieving information about a file from the VirusTotal v2 API.
    """
    resp = vtotal_v2.request("file/report", {"resource": FILE_ID})
    assert resp.response_code == 1
    assert resp.json()["scans"]


def test_file_info_v3(vtotal_v3):
    """
    Test for retrieving information about a file from the VirusTotal v3 API.
    """
    resp = vtotal_v3.request(f"files/{FILE_ID}")
    assert resp.status_code == 200
    assert resp.object_type == "file"
    assert resp.data["attributes"]
    assert resp.data["attributes"]["last_analysis_results"]


def test_compatibility():
    """
    Test COMPATIBILITY_ENABLED parameter on Virustotal class.
    """
    vtotal = virustotal_python.Virustotal(API_VERSION="v3", COMPATIBILITY_ENABLED=True)
    resp = vtotal.request(f"files/{FILE_ID}")
    assert resp["status_code"] == 200
    assert resp["json_resp"]["data"]["type"] == "file"
    assert resp["json_resp"]["data"]["attributes"]


def test_scan_url_info_v2(vtotal_v2):
    """
    Test scanning URL and retrieving the scan results from the VirusTotal v2 API.
    """
    # Send the URLs to VirusTotal for analysis
    resp = vtotal_v2.request("url/scan", params={"url": URL_DOMAIN}, method="POST")
    assert resp.status_code == 200
    data = resp.json()
    # Obtain scan_id
    scan_id = data["scan_id"]
    # Request report for URL analysis
    analysis_resp = vtotal_v2.request("url/report", params={"resource": scan_id})
    assert analysis_resp.status_code == 200
    assert analysis_resp.response_code == 1
    data = analysis_resp.json()
    assert data["scan_id"]
    assert data["verbose_msg"]
    assert data["url"] == f"http://{URL_DOMAIN}/"
    assert data["scan_date"]


def test_scan_url_info_v3(vtotal_v3):
    """
    Test scanning URL and retrieving the scan results from the VirusTotal v3 API.
    """
    resp = vtotal_v3.request("urls", data={"url": URL_DOMAIN}, method="POST")
    assert resp.status_code == 200
    assert resp.data["id"]
    # URL safe encode URL in base64 format
    # https://developers.virustotal.com/v3.0/reference#url
    url_id = urlsafe_b64encode(URL_DOMAIN.encode()).decode().strip("=")
    print(f"URL: {URL_DOMAIN} ID: {url_id}")
    # Obtain the analysis results for the URL using the url_id
    analysis_resp = vtotal_v3.request(f"urls/{url_id}")
    assert analysis_resp.status_code == 200
    assert analysis_resp.object_type == "url"
    assert analysis_resp.data["attributes"]


def test_domain_info_v2(vtotal_v2):
    """
    Test for retrieving domain information from the VirusTotal v2 API.
    """
    resp = vtotal_v2.request("domain/report", params={"domain": URL_DOMAIN})
    assert resp.response_code == 1
    json = resp.json()
    assert json["Alexa rank"]
    assert json["Alexa domain info"]
    assert json["Webutation domain info"]["Verdict"]
    assert json["whois_timestamp"]


def test_domain_info_v3(vtotal_v3):
    """
    Test for retrieving domain information from the VirusTotal v3 API.
    """
    resp = vtotal_v3.request(f"domains/{URL_DOMAIN}")
    assert resp.status_code == 200
    assert resp.object_type == "domain"
    data = resp.data
    assert isinstance(data["links"], dict)
    assert data["attributes"]["last_analysis_results"]
    assert data["attributes"]["creation_date"]


def test_retrieve_comment_file_id_v3(vtotal_v3):
    """
    Test for retrieving a comment for a given file ID.
    """
    resp = vtotal_v3.request(f"files/{FILE_ID}/comments", params={"limit": 2})
    assert resp.status_code == 200
    assert resp.links
    assert resp.meta
    assert resp.cursor
    json = resp.data
    # Retrieve first comment text
    assert json[0]["attributes"]["text"]
    # Retrieve second comment tags
    assert json[1]["attributes"]["votes"] and isinstance(
        json[1]["attributes"]["votes"], dict
    )


def test_retrieve_comment_file_id_v2(vtotal_v2):
    """
    Test for retrieving a comment for a given file ID using the VirusTotal v2 API.
    """
    resp = vtotal_v2.request("comments/get", params={"resource": FILE_ID})
    assert resp.status_code == 200
    assert resp.response_code == 1
    json = resp.json()
    for commentdata in json["comments"]:
        assert commentdata["date"]
        assert commentdata["comment"]


def test_retrieve_comment_latest_v3(vtotal_v3):
    """
    Test for retrieveing the latest 10 comments made on VirusTotal.
    """
    resp = vtotal_v3.request("comments", params={"limit": 10})
    assert resp.status_code == 200
    assert resp.links
    assert resp.meta
    assert resp.cursor
    json = resp.data
    assert json[0]["attributes"]["date"]
    assert len(json) == 10


def test_retrieve_ip_info_v2(vtotal_v2):
    """
    Test for retrieving information about an IP address using the VirusTotal v2 API.
    """
    resp = vtotal_v2.request("ip-address/report", params={"ip": IP})
    assert resp.status_code == 200
    assert resp.response_code == 1
    json = resp.json()
    assert json["as_owner"] == "GOOGLE"
    assert json["country"] == "US"
    assert json["verbose_msg"] == "IP address in dataset"
    for sample in json["detected_communicating_samples"]:
        assert sample["date"]
        assert sample["positives"]
        assert sample["sha256"]
        assert sample["total"]


def test_retrieve_ip_info_v3(vtotal_v3):
    """
    Test for retrieving information about an IP address.
    """
    resp = vtotal_v3.request(f"ip_addresses/{IP}")
    assert resp.status_code == 200
    data = resp.data
    assert data["attributes"]["as_owner"] == "GOOGLE"
    assert data["attributes"]["country"] == "US"
    assert data["attributes"]["last_analysis_stats"]
    assert data["attributes"]["reputation"]
    assert resp.object_type == "ip_address"


def test_retrieve_graph_v3(vtotal_v3):
    """
    Test for retrieving the latest 3 graphs made on VirusTotal.
    """
    resp = vtotal_v3.request("graphs", params={"limit": 3})
    assert resp.status_code == 200
    assert len(resp.data) == 3
    data = resp.data
    assert data[0]["attributes"]["graph_data"]
    assert resp.links
    assert resp.meta
    assert resp.cursor


def test_search_v3(vtotal_v3):
    """
    Test searching the VirusTotal API.
    """
    resp = vtotal_v3.request("search", params={"query": URL_DOMAIN})
    assert resp.status_code == 200
    assert resp.links
    assert resp.object_type
    data = resp.data
    assert data[0]["attributes"]["creation_date"]
    assert data[0]["attributes"]["last_analysis_results"]
    assert data[0]["attributes"]["last_analysis_stats"]
    assert data[0]["attributes"]["last_dns_records"]
    assert data[0]["attributes"]["last_https_certificate"]
    assert data[0]["attributes"]["total_votes"]


def test_metadata_v3(vtotal_v3):
    """
    Test retrieving metadata from the VirusTotal API.
    """
    resp = vtotal_v3.request("metadata")
    assert resp.status_code == 200
    engines_dict = resp.data["engines"]
    assert engines_dict.keys()
    assert "Microsoft" in engines_dict.keys()


def test_contextmanager_v2():
    """
    Test basic Context Manager support.
    """
    with virustotal_python.Virustotal() as vtotal:
        # Retrieve information about an IP address
        resp = vtotal.request("ip-address/report", params={"ip": IP})
        assert resp.status_code == 200
        data = resp.json()
        assert data["as_owner"] == "GOOGLE"
        assert data["country"] == "US"


def test_contextmanager_v3():
    """
    Test basic Context Manager support.
    """
    with virustotal_python.Virustotal(API_VERSION="v3") as vtotal:
        # Retrieve information about an IP address
        resp = vtotal.request(f"ip_addresses/{IP}")
        assert resp.status_code == 200
        data = resp.data
        assert data["id"] == IP
        assert data["attributes"]["as_owner"] == "GOOGLE"
        assert data["attributes"]["country"] == "US"
