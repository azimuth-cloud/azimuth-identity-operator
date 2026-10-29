import asyncio
import threading
from collections.abc import Iterator

import httpx
import pytest
from pytest_httpserver import HTTPServer, RequestMatcher
from pytest_httpserver.httpserver import Request, RequestHandler, Response
from pytest_httpx import HTTPXMock

from azimuth_identity.config import settings
from azimuth_identity.keycloak.client import Auth

TOKEN_PATH = "/realms/master/protocol/openid-connect/token"
TOKEN_URL = f"{settings.keycloak.base_url}{TOKEN_PATH}"
GROUPS_URL = f"{settings.keycloak.base_url}/test/groups"
CONCURRENCY = 5
POOL_SIZE = 5


@pytest.fixture
def auth_client() -> httpx.AsyncClient:
    """A Keycloak client with no token fetched yet."""
    client = httpx.AsyncClient()
    client.auth = Auth(client, TOKEN_URL)
    return client


@pytest.fixture
def auth(auth_client: httpx.AsyncClient) -> Auth:
    """The Auth instance attached to `auth_client`."""
    assert isinstance(auth_client.auth, Auth)
    return auth_client.auth


@pytest.mark.asyncio
async def test_fetches_token_on_first_request(
    httpx_mock: HTTPXMock, auth_client: httpx.AsyncClient
) -> None:
    """The first request fetches a token and then sends it as a bearer token."""
    httpx_mock.add_response(
        url=TOKEN_URL, method="POST", json={"access_token": "fresh-token"}
    )
    httpx_mock.add_response(
        url=GROUPS_URL,
        match_headers={"Authorization": "Bearer fresh-token"},
        json=[],
    )

    async with auth_client:
        response = await auth_client.get(GROUPS_URL)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_refreshes_expired_token_and_retries(
    httpx_mock: HTTPXMock, auth_client: httpx.AsyncClient, auth: Auth
) -> None:
    """A 401 for an expired token triggers a refresh and the request is retried."""
    httpx_mock.add_response(
        url=GROUPS_URL,
        match_headers={"Authorization": "Bearer expired-token"},
        status_code=401,
    )
    httpx_mock.add_response(
        url=TOKEN_URL, method="POST", json={"access_token": "fresh-token"}
    )
    httpx_mock.add_response(
        url=GROUPS_URL,
        match_headers={"Authorization": "Bearer fresh-token"},
        json=[],
    )
    # Simulate a token that has expired since it was issued
    auth._token = "expired-token"

    async with auth_client:
        response = await auth_client.get(GROUPS_URL)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_concurrent_requests_refresh_token_once(
    httpx_mock: HTTPXMock, auth_client: httpx.AsyncClient, auth: Auth
) -> None:
    """Concurrent requests that all receive a 401 only refresh the token once."""
    httpx_mock.add_response(
        url=GROUPS_URL,
        match_headers={"Authorization": "Bearer expired-token"},
        status_code=401,
        is_reusable=True,
    )
    httpx_mock.add_response(
        url=TOKEN_URL, method="POST", json={"access_token": "fresh-token"}
    )
    httpx_mock.add_response(
        url=GROUPS_URL,
        match_headers={"Authorization": "Bearer fresh-token"},
        json=[],
        is_reusable=True,
    )
    # Simulate a token that has expired since it was issued
    auth._token = "expired-token"

    async with auth_client:
        responses = await asyncio.gather(
            *(auth_client.get(GROUPS_URL) for _ in range(CONCURRENCY))
        )

    assert [r.status_code for r in responses] == [200] * CONCURRENCY
    # Only one of the requests should have refreshed the token
    assert len(httpx_mock.get_requests(url=TOKEN_URL)) == 1


@pytest.mark.asyncio
async def test_token_request_failure_is_raised(
    httpx_mock: HTTPXMock, auth_client: httpx.AsyncClient
) -> None:
    """An error response from the token endpoint is raised to the caller."""
    httpx_mock.add_response(url=TOKEN_URL, method="POST", status_code=500)

    async with auth_client:
        with pytest.raises(httpx.HTTPStatusError):
            await auth_client.get(GROUPS_URL)


class HoldUnauthorised:
    """
    A handler that doesn't send 401 responses immediately so that connections
    are kept open. Responses to requests with an expired token are not sent until
    `hold_unauthorised` of them have arrived.

    `hold_unauthorised` should be equal to the client connection pool size to ensure
    that enough requests are sent/received to fill the client's connection pool.
    This ensures that every connection in the client's pool is in use at the point
    where the token needs to be refreshed.
    """

    def __init__(self, hold_unauthorised: int, unauthorised: RequestHandler) -> None:
        """Initialise the hold with the number of requests to wait for.

        Once released, each response is produced by the `unauthorised` handler.
        """
        self.hold_unauthorised = hold_unauthorised
        self.unauthorised = unauthorised
        self.count = 0
        self.lock = threading.Lock()
        self.release = threading.Event()

    def __call__(self, request: Request) -> Response:
        """
        Handle requests with an expired token.

        The server is threaded so this is called concurrently, once per request,
        and blocks until enough requests have arrived to fill the client's
        connection pool.
        """
        # Create a lock on the shared counter, as requests can arrive on
        # different threads
        with self.lock:
            # Increment the counter when an unauthorised request with an expired
            # token is received
            self.count += 1
            # If we receive hold_unauthorised requests with expired tokens
            # release all of the connections
            if self.count >= self.hold_unauthorised:
                self.release.set()
        # We haven't reached hold_unauthorised, so hold the connection open.
        # Timeout prevents a bad test from hanging indefinitely. If the timeout
        # expires, then the 401 is sent anyway and the test fails on the client
        # side.
        self.release.wait(timeout=10)
        # Send the 401 response for this request
        return self.unauthorised.respond(request)


@pytest.fixture
def keycloak() -> Iterator[HTTPServer]:
    """
    Provide a threaded fake Keycloak server that handles requests concurrently.

    The server must be threaded so that requests being held back by
    `HoldUnauthorised` don't prevent other requests from being served. It
    simulates Keycloak with an access token that has been rotated:

    * POSTs to the token endpoint return "fresh-token".
    * GETs to `/test/groups` with "fresh-token" succeed with an empty list.
    * GETs to `/test/groups` with "expired-token" get a 401, but only once
      `POOL_SIZE` of them have arrived, so the client's pool is full when it
      needs to refresh the token.
    """

    with HTTPServer(threaded=True) as server:
        # Token requests (POST) always succeed and return fresh-token
        server.expect_request(TOKEN_PATH, method="POST").respond_with_json(
            {"access_token": "fresh-token"}
        )
        # Requests to other paths (GET) that provide fresh-token succeed
        server.expect_request(
            "/test/groups", headers={"Authorization": "Bearer fresh-token"}
        ).respond_with_json([])

        # Build a 401 unauthorised response to pass to the HoldUnauthorised handler,
        # which is returned once requests are released
        unauthorised = RequestHandler(server.create_matcher("/test/groups"))
        unauthorised.respond_with_json({"error": "HTTP 401 Unauthorised"}, status=401)

        # Requests authenticated with the expired token are held until POOL_SIZE,
        # then get the 401 unauthorised response
        server.expect_request(
            "/test/groups", headers={"Authorization": "Bearer expired-token"}
        ).respond_with_handler(HoldUnauthorised(POOL_SIZE, unauthorised))
        # Hand the running server to the test
        yield server


@pytest.mark.asyncio
async def test_concurrent_token_refresh_does_not_exhaust_pool(
    keycloak: HTTPServer,
) -> None:
    """
    When as many requests as there are pool connections all receive a 401 for
    an expired token, the token refresh must still be able to get a connection.
    """
    base_url = keycloak.url_for("")
    async with httpx.AsyncClient(
        base_url=base_url,
        limits=httpx.Limits(max_connections=POOL_SIZE),
        timeout=httpx.Timeout(5.0, pool=1.0),
    ) as client:
        auth = Auth(client, f"{base_url}{TOKEN_PATH}")
        client.auth = auth
        # Simulate a token that has expired since it was issued
        auth._token = "expired-token"

        # Send enough concurrent requests to occupy every connection in the pool
        requests = [client.get("/test/groups") for _ in range(POOL_SIZE)]
        # Wait for responses to return for all of our requests. Timeout prevents
        # a bad test from hanging indefinitely.
        responses = await asyncio.wait_for(asyncio.gather(*requests), timeout=10)

    # Ensure that all responses were HTTP 200
    assert [r.status_code for r in responses] == [200] * POOL_SIZE
    # Search the keycloak request log to ensure that only one of the requests
    # actually refreshed the token
    keycloak.assert_request_made(RequestMatcher(TOKEN_PATH), count=1)
