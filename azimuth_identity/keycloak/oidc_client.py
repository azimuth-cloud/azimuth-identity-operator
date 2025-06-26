import logging

from azimuth_identity.models import v1alpha1 as api

from . import client as kc_client

LOGGER = logging.getLogger(__name__)


def merge(dict1: dict, dict2: dict) -> dict:
    """
    Recursively merges two dictionaries and produces a new dictionary.
    """
    merged = dict1.copy()
    for key, value in dict2.items():
        if key in dict1 and isinstance(dict1[key], dict) and isinstance(value, dict):
            merged[key] = merge(dict1[key], value)
        else:
            merged[key] = value
    return merged


async def get_oidc_client(realm_name: str, client_id: str):
    """
    Returns a client by client ID.
    """
    response = await kc_client.get(
        f"/{realm_name}/clients", params={"clientId": client_id}
    )
    return next(iter(response.json()), None)


async def ensure_oidc_client(realm_name: str, oidc_client: api.OIDCClient):
    """
    Ensures that an OIDC client exists for the given service.
    """
    # Derive the client ID for the service
    client_id = oidc_client.spec.client_id or oidc_client.metadata.name
    # See if the client already exists
    existing_client = (await get_oidc_client(realm_name, client_id)) or {}
    existing_client.pop("access", None)
    # Update with what we think the client should look like
    next_client = merge(
        existing_client,
        {
            "enabled": True,
            "clientId": client_id,
            "protocol": "openid-connect",
            "publicClient": oidc_client.spec.public,
            "redirectUris": oidc_client.spec.redirect_uris,
            # Enable the required grant types if present in the list
            #   authorization code
            "standardFlowEnabled": (
                api.OIDCClientGrantType.AUTHORIZATION_CODE
                in oidc_client.spec.grant_types
            ),
            #   client credentials
            "serviceAccountsEnabled": (
                api.OIDCClientGrantType.CLIENT_CREDENTIALS
                in oidc_client.spec.grant_types
            ),
            #   device code + refresh tokens
            "attributes": {
                "oauth2.device.authorization.grant.enabled": (
                    "true"
                    if api.OIDCClientGrantType.DEVICE_CODE
                    in oidc_client.spec.grant_types
                    else "false"
                ),
                "use.refresh.tokens": "true",
            },
            # Ensure deprecated grant types are disabled
            #   implicit
            "implicitFlowEnabled": False,
            #   password
            "directAccessGrantsEnabled": False,
        },
    )
    if not existing_client:
        LOGGER.info("Creating OIDC client '%s' in realm - %s", client_id, realm_name)
        response = await kc_client.post(f"/{realm_name}/clients", json=next_client)
        # The Keycloak API does not return a representation in the create response,
        # but it does return the URL to get one in the location header
        response = await kc_client.get(response.headers["location"])
        next_client = response.json()
    elif next_client != existing_client:
        LOGGER.info("Updating OIDC client '%s' in realm - %s", client_id, realm_name)
        kc_id = next_client.pop("id")
        await kc_client.put(f"/{realm_name}/clients/{kc_id}", json=next_client)
        # Update the representation of the client after the changes
        response = await kc_client.get(f"/{realm_name}/clients/{kc_id}")
        next_client = response.json()
    return next_client["clientId"], next_client.get("secret")


async def remove_oidc_client(realm_name: str, oidc_client: api.OIDCClient):
    """
    Ensures that the specified OIDC client is removed.
    """
    client_id = oidc_client.spec.client_id or oidc_client.metadata.name
    LOGGER.info("Deleting OIDC client '%s' in realm - %s", client_id, realm_name)
    # Try to find the client by its client ID and use its internal ID to delete it
    client = await get_oidc_client(realm_name, client_id)
    if client:
        await kc_client.delete(f"/{realm_name}/clients/{client['id']}")
