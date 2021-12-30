"""Tests for virustotal-python.
"""
import os
import typing
import virustotal_python
import time
import pytest

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
# Example IP address (Cloudflare DNS)
IP = "1.1.1.1"
# Example ID of a graph
## NOTE: There are no comments on this graph so an empty list is returned
GRAPH_ID = "g70fae134aefc4e2f90f069aba47d15a92e0073564310443aa0b6ca3384f5240d"
# URL/domain identifier
URL_DOMAIN = "github.com"
# Example comment ID
COMMENT_ID = (
    "f-9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115-07457619"
)


def check_resp_code(resp: typing.Union[virustotal_python.Virustotal, dict]) -> bool:
    """Check the HTTP status code returned from the VirusTotal API is 200 (OK)."""
    # Using COMPATIBILITY_ENABLED parameter
    if isinstance(resp, dict):
        assert resp["status_code"] == 200
    else:
        assert resp.status_code == 200


@pytest.fixture(autouse=True)
def avoid_rate_limit(request) -> None:
    """Fixture to wait 15 seconds between API requests to avoid the VirusTotal API rate limit.
    The Public API is limited to ... a rate of 4 requests per minute.

    Args:
        request: request-context object - https://docs.pytest.org/en/6.2.x/fixture.html#request-context
    """

    def fin():
        """Finaliser function to wait 15 seconds."""
        time.sleep(15)

    request.addfinalizer(fin)


@pytest.fixture
def vtotal(request) -> virustotal_python.Virustotal:
    """Fixture to initialise the Virustotal class with provided parameters for a test.

    Args:
        request: request-context object - https://docs.pytest.org/en/6.2.x/fixture.html#request-context

    Returns:
        virustotal_python.Virustotal: A virustotal_python.Virustotal object.
    """
    return virustotal_python.Virustotal(**request.param)


class Test_Virustotal:
    """A class containing tests for the Virustotal class."""

    @pytest.mark.parametrize(
        "vtotal",
        [{"API_VERSION": 2, "COMPATIBILITY_ENABLED": True}],
        indirect=True,
    )
    def test_v2_compatibility(self, vtotal: virustotal_python.Virustotal) -> None:
        """Test Virustotal class `COMPATIBILITY_ENABLED` parameter behaviour with the v2 API.

        Args:
            vtotal (virustotal_python.Virustotal): The Virustotal object returned from the `vtotal` fixture.
        """
        # Get domain report
        resp = vtotal.request("domain/report", params={"domain": URL_DOMAIN})
        check_resp_code(resp)

    @pytest.mark.parametrize(
        "vtotal",
        [{"API_VERSION": 3, "COMPATIBILITY_ENABLED": True}],
        indirect=True,
    )
    def test_v3_compatibility(self, vtotal: virustotal_python.Virustotal) -> None:
        """Test Virustotal class `COMPATIBILITY_ENABLED` parameter behaviour with the v3 API.

        Args:
            vtotal (virustotal_python.Virustotal): The Virustotal object returned from the `vtotal` fixture.
        """
        # Get domain report
        resp = vtotal.request(f"domains/{URL_DOMAIN}")
        check_resp_code(resp)
