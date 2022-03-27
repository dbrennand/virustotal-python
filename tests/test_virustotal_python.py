"""Tests for virustotal-python.
"""
import virustotal_python
import pytest
import pytest_mock

@pytest.fixture
def mock_os_environ(mocker: pytest_mock.MockerFixture) -> None:
    """Mocker fixture for `os.environ`.

    Args:
        mocker (pytest_mock.MockerFixture): A pytest_mock.MockerFixture providing a
            thin-wrapper around the patching API from the mock library.
    """
    mocker.patch.dict("os.environ", dict(VIRUSTOTAL_API_KEY="API key"))

def test_virustotal_apikey_env(mock_os_environ) -> None:
    """Test `Virustotal` environment variable `VIRUSTOTAL_API_KEY`.

    Args:
        mock_os_environ: Pytest fixture function to mock `os.environ`.
    """
    vtotal = virustotal_python.Virustotal()
    assert vtotal.API_KEY == "API key"

def test_virustotal(mocker: pytest_mock.MockerFixture) -> None:
    """Test `Virustotal` parameters.

    Args:
        mocker (pytest_mock.MockerFixture): A pytest_mock.MockerFixture providing a
            thin-wrapper around the patching API from the mock library.
    """
    keyword_arguments = {"API_KEY": "test", "API_VERSION": 3, "PROXIES": {"http": "http://10.10.1.10:3128"}, "TIMEOUT": 10}
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
    assert "An API key is required to interact with the VirusTotal API.\nProvide one to the API_KEY parameter or by setting the environment variable 'VIRUSTOTAL_API_KEY'." == str(execinfo.value)

def test_virustotal_api_version_value_error() -> None:
    """Test `Virustotal` raises `ValueError` when an unsupported `API_VERSION` is provided."""
    with pytest.raises(ValueError) as execinfo:
        virustotal_python.Virustotal(API_KEY="test", API_VERSION="test")
    assert "The API version 'test' is not a valid VirusTotal API version.\nValid API versions are 'v2', 2, 'v3' and 3." == str(execinfo.value)

def test_request_notimplemented_error() -> None:
    """Test `Virustotal.request()` raises `NotImplementedError` when an unsupported `method` is provided."""
    with pytest.raises(NotImplementedError) as execinfo:
        vtotal = virustotal_python.Virustotal(API_KEY="test")
        vtotal.request("test", method="test")
    assert "The request method 'test' is not implemented." == str(execinfo.value)

"""
# Tests

Test request `large_file` parameter

Test VirustotalResponse properties and methods

Test VirustotalError properties and methods
"""
