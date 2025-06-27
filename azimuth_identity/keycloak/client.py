import asyncio
import logging

import httpx

from ..config import settings  # noqa: TID252

LOGGER = logging.getLogger(__name__)


class Auth(httpx.Auth):
    """
    Authenticator for Keycloak requests.
    """

    requires_response_body = True

    def __init__(self, client, token_url):
        self._client = client
        self._token_url = token_url
        self._token = None
        self._lock = asyncio.Lock()

    async def refresh_token(self):
        # We want to make sure only one request refreshes the token
        token = self._token
        async with self._lock:
            # If someone else changed the token in the time it took us
            # to acquire the lock, there is nothing for us to do
            # Otherwise, fetch a new token
            if self._token == token:
                LOGGER.info("Refreshing Keycloak admin token")
                response = await self._client.post(
                    self._token_url,
                    data={
                        "grant_type": "password",
                        "client_id": settings.keycloak.client_id,
                        "username": settings.keycloak.username,
                        "password": settings.keycloak.password,
                    },
                    auth=None,
                )
                response.raise_for_status()
                self._token = response.json()["access_token"]

    async def async_auth_flow(self, request):
        if self._token is None:
            await self.refresh_token()
        while True:
            request.headers["Authorization"] = f"Bearer {self._token}"
            response = yield request
            if response.status_code == 401:
                await self.refresh_token()
                continue
            response.raise_for_status()
            break


# The client must be initialised inside the event loop for the auth lock to work
# correctly
kc_client = None


async def init():
    global kc_client
    kc_client = httpx.AsyncClient(base_url=f"{settings.keycloak.base_url}/admin/realms")
    kc_client.auth = Auth(
        kc_client,
        (
            f"{settings.keycloak.base_url}/realms/{settings.keycloak.client_realm}"
            "/protocol/openid-connect/token"
        ),
    )


async def close():
    await kc_client.aclose()


async def get(*args, **kwargs):
    return await kc_client.get(*args, **kwargs)


async def post(*args, **kwargs):
    return await kc_client.post(*args, **kwargs)


async def put(*args, **kwargs):
    return await kc_client.put(*args, **kwargs)


async def delete(*args, **kwargs):
    return await kc_client.delete(*args, **kwargs)
