"""Tests for virustotal-python.
"""

import virustotal_python
import json
import requests
import pytest
import pytest_mock
import requests_mock as req_mock

with open("tests/example.json") as json_file:
    example_json = json.dumps(json.load(json_file))


@pytest.fixture
def mock_http_request(requests_mock: req_mock.Mocker) -> None:
    """Fixture to mock HTTP requests made by the `Virustotal.request()` method.

    Args:
        requests_mock (req_mock.Mocker): A req_mock.Mocker providing a
            thin-wrapper around patching the `requests` library.
    """
    requests_mock.register_uri(
        req_mock.ANY,
        req_mock.ANY,
        status_code=200,
        text=example_json,
        headers={"test": "test"},
    )


def test_virustotal_apikey_env(mocker: pytest_mock.MockerFixture) -> None:
    """Test `Virustotal` environment variable `VIRUSTOTAL_API_KEY`.

    Args:
        mocker (pytest_mock.MockerFixture): A pytest_mock.MockerFixture providing a
            thin-wrapper around the patching API from the mock library.
    """
    mocker.patch.dict("os.environ", dict(VIRUSTOTAL_API_KEY="API key"))
    vtotal = virustotal_python.Virustotal()
    assert vtotal.API_KEY == "API key"


def test_virustotal(mocker: pytest_mock.MockerFixture) -> None:
    """Test `Virustotal` parameters.

    Args:
        mocker (pytest_mock.MockerFixture): A pytest_mock.MockerFixture providing a
            thin-wrapper around the patching API from the mock library.
    """
    keyword_arguments = {
        "API_KEY": "test",
        "API_VERSION": 3,
        "PROXIES": {"http": "http://10.10.1.10:3128"},
        "TIMEOUT": 5.0,
    }
    mock_vtotal = mocker.patch("virustotal_python.Virustotal")
    virustotal_python.Virustotal(**keyword_arguments)
    mock_vtotal.assert_called_with(**keyword_arguments)


def test_virustotal_context_manager() -> None:
    """Test `Virustotal` context manager support."""
    with virustotal_python.Virustotal(API_KEY="test") as vtotal:
        vtotal.__exit__("", "", "")


def test_virustotal_api_key_value_error() -> None:
    """Test `Virustotal` raises `ValueError` when no `API_KEY` is provided."""
    with pytest.raises(ValueError) as execinfo:
        virustotal_python.Virustotal()
    assert (
        "An API key is required to interact with the VirusTotal API.\nProvide one to the API_KEY parameter or by setting the environment variable 'VIRUSTOTAL_API_KEY'."
        == str(execinfo.value)
    )


def test_virustotal_api_version_value_error() -> None:
    """Test `Virustotal` raises `ValueError` when an unsupported `API_VERSION` is provided."""
    with pytest.raises(ValueError) as execinfo:
        virustotal_python.Virustotal(API_KEY="test", API_VERSION="test")
    assert (
        "The API version 'test' is not a valid VirusTotal API version.\nValid API versions are 'v2', 2, 'v3' and 3."
        == str(execinfo.value)
    )


def test_request_notimplemented_error() -> None:
    """Test `Virustotal.request()` raises `NotImplementedError` when an unsupported `method` is provided."""
    with pytest.raises(NotImplementedError) as execinfo:
        vtotal = virustotal_python.Virustotal(API_KEY="test")
        vtotal.request("test", method="test")
    assert "The request method 'test' is not implemented." == str(execinfo.value)


def test_request_large_file(requests_mock: req_mock.Mocker) -> None:
    """Test `Virustotal.request()` `large_file` parameter.

    Args:
        requests_mock (req_mock.Mocker): A req_mock.Mocker providing a
            thin-wrapper around patching the `requests` library.
    """
    requests_mock.register_uri(
        "GET",
        "https://www.virustotal.com/api/v3/files/upload_url",
        status_code=200,
        json={
            "data": "http://www.virustotal.com/_ah/upload/AMmfu6b-_DXUeFe36Sb3b0F4B8mH9Nb-CHbRoUNVOPwG/"
        },
    )
    requests_mock.register_uri(
        "POST",
        "http://www.virustotal.com/_ah/upload/AMmfu6b-_DXUeFe36Sb3b0F4B8mH9Nb-CHbRoUNVOPwG/",
        status_code=200,
        json={"data": {"type": "analysis", "id": "test=="}},
    )
    with virustotal_python.Virustotal(API_KEY="test", API_VERSION=3) as vtotal:
        resp = vtotal.request("files/upload_url")
        large_upload_url = resp.data
        large_upload_resp = vtotal.request(
            large_upload_url, method="POST", large_file=True
        )
    assert large_upload_resp.data == {"type": "analysis", "id": "test=="}


def test_virustotal_response_headers(mock_http_request) -> None:
    """Test `VirustotalResponse.headers` property.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.headers == {"test": "test"}


def test_virustotal_response_status_code(mock_http_request) -> None:
    """Test `VirustotalResponse.status_code` property.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.status_code == 200


def test_virustotal_response_text(mock_http_request) -> None:
    """Test `VirustotalResponse.text` property.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.text == example_json


def test_virustotal_response_requests_response(mock_http_request) -> None:
    """Test `VirustotalResponse.requests_response` property.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert type(resp.requests_response) == requests.Response


def test_virustotal_response_links(mock_http_request) -> None:
    """Test `VirustotalResponse.links` property.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.links == json.loads(example_json)["links"]


def test_virustotal_response_meta(mock_http_request) -> None:
    """Test `VirustotalResponse.meta` property.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.meta == json.loads(example_json)["meta"]


def test_virustotal_response_cursor(mock_http_request) -> None:
    """Test `VirustotalResponse.cursor` property.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.cursor == json.loads(example_json)["meta"]["cursor"]


def test_virustotal_response_cursor_none(requests_mock: req_mock.Mocker) -> None:
    """Test `VirustotalResponse.cursor` property returns `None` if `meta` key
    is not present in the JSON response.

    Args:
        requests_mock (req_mock.Mocker): A req_mock.Mocker providing a
            thin-wrapper around patching the `requests` library.
    """
    requests_mock.register_uri(
        req_mock.ANY,
        req_mock.ANY,
        status_code=200,
    )
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.cursor == None


def test_virustotal_response_data(mock_http_request) -> None:
    """Test `VirustotalResponse.data` property.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.data == json.loads(example_json)["data"]


def test_virustotal_response_object_type_list(mock_http_request) -> None:
    """Test `VirustotalResponse.object_type` property returns a `list` of all the object types.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    obj_types = []
    for comment in resp.data:
        obj_types.append(comment["type"])
    assert resp.object_type == obj_types


def test_virustotal_response_object_type_str(requests_mock: req_mock.Mocker) -> None:
    """Test `VirustotalResponse.object_type` property returns a `str` of a single
    object type.

    Args:
        requests_mock (req_mock.Mocker): A req_mock.Mocker providing a
            thin-wrapper around patching the `requests` library.
    """
    requests_mock.register_uri(
        req_mock.ANY,
        req_mock.ANY,
        status_code=200,
        json={"data": {"type": "test type"}},
    )
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.object_type == "test type"


def test_virustotal_response_object_type_none(requests_mock: req_mock.Mocker) -> None:
    """Test `VirustotalResponse.object_type` property returns `None` when the data property
    is neither a `list` or `dict`.

    Example endpoint: https://developers.virustotal.com/reference/files-upload-url

    Args:
        requests_mock (req_mock.Mocker): A req_mock.Mocker providing a
            thin-wrapper around patching the `requests` library.
    """
    requests_mock.register_uri(
        req_mock.ANY,
        req_mock.ANY,
        status_code=200,
        json={
            "data": "http://www.virustotal.com/_ah/upload/AMmfu6b-_DXUeFe36Sb3b0F4B8mH9Nb-CHbRoUNVOPwG/"
        },
    )
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.object_type == None


def test_virustotal_response_response_code(mock_http_request) -> None:
    """Test `VirustotalResponse.response_code` property.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.response_code == json.loads(example_json)["response_code"]


def test_virustotal_response_json(mock_http_request) -> None:
    """Test `VirustotalResponse.json()` method.

    Args:
        mock_http_request (`mock_http_request()`): A pytest fixture to
            to mock HTTP requests made by the `Virustotal.request()` method.
    """
    with virustotal_python.Virustotal("test") as vtotal:
        resp = vtotal.request("test")
    assert resp.json() == json.loads(example_json)


def test_virustotal_error(requests_mock: req_mock.Mocker) -> None:
    """Test `VirustotalError.error()` method and string dunder.

    Args:
        requests_mock (req_mock.Mocker): A req_mock.Mocker providing a
            thin-wrapper around patching the `requests` library.
    """
    requests_mock.register_uri(
        req_mock.ANY,
        req_mock.ANY,
        status_code=404,
        json={
            "error": {
                "code": "NotFoundError",
                "message": 'URL "thisurlidmakesnosenseatall" not found',
            }
        },
    )
    with pytest.raises(virustotal_python.VirustotalError) as execinfo:
        vtotal = virustotal_python.Virustotal("test")
        vtotal.request("test")
    assert (
        'Error NotFoundError (404): URL "thisurlidmakesnosenseatall" not found'
        == str(execinfo.value)
    )


def test_virustotal_error_no_code_message(requests_mock: req_mock.Mocker) -> None:
    """Test `VirustotalError.error()` method and string dunder with no code or message.

    Args:
        requests_mock (req_mock.Mocker): A req_mock.Mocker providing a
            thin-wrapper around patching the `requests` library.
    """
    requests_mock.register_uri(req_mock.ANY, req_mock.ANY, status_code=400)
    with pytest.raises(virustotal_python.VirustotalError) as execinfo:
        vtotal = virustotal_python.Virustotal("test")
        vtotal.request("test")
    assert "Error Unknown (400): No message" == str(execinfo.value)


def test_virustotal_error_text_only(requests_mock: req_mock.Mocker) -> None:
    """Test `VirustotalError.error()` method and string dunder with `requests.Response.text` present.

    Args:
        requests_mock (req_mock.Mocker): A req_mock.Mocker providing a
            thin-wrapper around patching the `requests` library.
    """
    requests_mock.register_uri(
        req_mock.ANY, req_mock.ANY, status_code=400, text="Request failed"
    )
    with pytest.raises(virustotal_python.VirustotalError) as execinfo:
        vtotal = virustotal_python.Virustotal("test")
        vtotal.request("test")
    assert "Error Unknown (400): Request failed" == str(execinfo.value)
