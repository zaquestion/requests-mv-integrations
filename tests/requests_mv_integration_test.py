import pytest
import requests

from requests_mv_integrations import RequestMvIntegration
from requests_mv_integrations.exceptions import (
    TuneRequestBaseError,
    TuneRequestServiceError,
    TuneRequestModuleError,
)

from requests_mv_integrations.errors import TuneRequestErrorCodes

@pytest.fixture
def request_mv_integration_object():
    obj = RequestMvIntegration()
    return obj


_test_object = (
    (requests.exceptions.ConnectTimeout, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.ReadTimeout, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.Timeout, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.HTTPError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_HTTP),
    (BrokenPipeError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT),
    (ConnectionError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT),
    (requests.packages.urllib3.exceptions.ProtocolError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT),
    (requests.packages.urllib3.exceptions.ReadTimeoutError, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.TooManyRedirects, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_REDIRECTS),
    (requests.exceptions.RequestException, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST),
    (TuneRequestBaseError, TuneRequestBaseError, TuneRequestErrorCodes.REQ_ERR_UNEXPECTED),
    (Exception, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_SOFTWARE),
)


class TestRequestMvIntegration:
    """
    A test class, for testing RequestMvIntegration methods.
    """
    @pytest.mark.parametrize("requests_error, mv_integration_error, error_code", _test_object)
    def test_request_raised_exceptions(
            self,
            monkeypatch,
            request_mv_integration_object,
            requests_error,
            mv_integration_error,
            error_code
    ):
        """
        Test RequestMvIntegration.request() exception handling, my mocking the call
        to RequestMvIntegration._request_retry()
        :param monkeypatch:
        :param request_mv_integration_object: An instance of RequestMvIntegration.
        :param requests_error: The exception which the mock function of
        RequestMvIntegration._request_retry() throws.
        :param mv_integration_error: The exception which tested RequestMvIntegration.request()
        should throw in response to <requests_error>.
        :return: assert that the expected thrown exception of RequestMvIntegration.request()
        is the correct one.
        """
        def mock__request_retry(*args, **kwargs):
            if requests_error == requests.packages.urllib3.exceptions.ReadTimeoutError:
                raise requests_error('pool', 'url', 'message')
            raise requests_error
        req = request_mv_integration_object
        monkeypatch.setattr(req, '_request_retry', mock__request_retry)
        try:
            req.request(
                request_method="Doesn't matter",
                request_url="Doesn't matter"
            )
        except Exception as e:
            assert(isinstance(e, mv_integration_error))
            assert(e.error_code == error_code)

