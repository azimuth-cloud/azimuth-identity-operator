import copy
import logging
import typing as t

from ..config import settings  # noqa: TID252
from ..models import v1alpha1 as api  # noqa: TID252
from . import client as kc_client

LOGGER = logging.getLogger(__name__)


async def ensure_platform_group(realm_name: str, platform: api.Platform):
    """
    Ensures that a group exists in Keycloak for the given platform.
    """
    # Get the existing group for the platform
    response = await kc_client.get(
        f"/{realm_name}/groups",
        params={
            "briefRepresentation": "false",
            "q": platform.metadata.name,
            "exact": "true",
        },
    )
    try:
        return next(
            group
            for group in response.json()
            if group["name"] == platform.metadata.name
        )
    except StopIteration:
        LOGGER.info(
            "Creating group for platform '%s' - %s", platform.metadata.name, realm_name
        )
        response = await kc_client.post(
            f"/{realm_name}/groups", json={"name": platform.metadata.name}
        )
        # The Keycloak API does not return a representation in the create response,
        # but it does return the URL to get one in the location header
        response = await kc_client.get(response.headers["location"])
        return response.json()


async def remove_platform_group(realm_name: str, platform: api.Platform):
    """
    Removes the group from Keycloak for the given platform.
    """
    # Get the existing group for the platform
    response = await kc_client.get(
        f"/{realm_name}/groups",
        params={
            "briefRepresentation": "false",
            "q": platform.metadata.name,
            "exact": "true",
        },
    )
    try:
        group = next(g for g in response.json() if g["name"] == platform.metadata.name)
    except StopIteration:
        # If there is no platform group, there is nothing to do
        return
    else:
        # Otherwise, delete the group
        LOGGER.info(
            "Deleting group for platform '%s' - %s", platform.metadata.name, realm_name
        )
        await kc_client.delete(f"/{realm_name}/groups/{group['id']}")


async def ensure_platform_service_subgroup(
    realm_name: str, group: dict[str, t.Any], service_name: str
):
    """
    Ensures that a subgroup exists for the given service.
    """
    try:
        return next(
            subgroup
            for subgroup in group["subGroups"]
            if subgroup["name"] == service_name
        )
    except StopIteration:
        LOGGER.info(
            "Creating subgroup for platform service '%s/%s' - %s",
            group["name"],
            service_name,
            realm_name,
        )
        response = await kc_client.post(
            f"/{realm_name}/groups/{group['id']}/children", json={"name": service_name}
        )
        response = await kc_client.get(response.headers["location"])
        return response.json()


async def prune_platform_service_subgroups(
    realm_name: str, platform: api.Platform, group: dict[str, t.Any]
):
    """
    Prunes subgroups for unrecognised platform services.
    """
    for subgroup in group.get("subGroups", []):
        # If the group name matches a recognised service, keep it
        if subgroup["name"] in platform.spec.zenith_services:
            continue
        # Otherwise, delete it
        LOGGER.info(
            "Deleting subgroup for platform service '%s/%s' - %s",
            group["name"],
            subgroup["name"],
            realm_name,
        )
        await kc_client.delete(f"/{realm_name}/groups/{subgroup['id']}")


async def ensure_platform_service_client(
    realm_name: str,
    platform: api.Platform,
    service_name: str,
    service: api.ZenithServiceSpec,
):
    """
    Ensures that an OIDC client exists for the given service.
    """
    # Derive the client ID for the service
    client_id = f"{platform.metadata.name}.{service_name}"
    # See if the client already exists
    response = await kc_client.get(
        f"/{realm_name}/clients", params={"clientId": client_id}
    )
    existing_client = next(iter(response.json()), {})
    existing_client.pop("access", None)
    # Update with what we think the client should look like
    next_client = copy.deepcopy(existing_client)
    base_url = f"{settings.keycloak.zenith_redirect_uri_scheme}://{service.fqdn}"
    next_client.update(
        {
            "clientId": client_id,
            "enabled": True,
            "protocol": "openid-connect",
            "clientAuthenticatorType": "client-secret",
            "baseUrl": base_url,
            "redirectUris": [
                f"{base_url}{settings.keycloak.zenith_redirect_uri_path}",
            ],
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "publicClient": False,
        }
    )
    if not existing_client:
        LOGGER.info(
            "Creating client for platform service '%s/%s' - %s",
            platform.metadata.name,
            service_name,
            realm_name,
        )
        response = await kc_client.post(f"/{realm_name}/clients", json=next_client)
        # The Keycloak API does not return a representation in the create response,
        # but it does return the URL to get one in the location header
        response = await kc_client.get(response.headers["location"])
        next_client = response.json()
    elif next_client != existing_client:
        LOGGER.info(
            "Updating client for platform service '%s/%s' - %s",
            platform.metadata.name,
            service_name,
            realm_name,
        )
        await kc_client.put(
            f"/{realm_name}/clients/{next_client.pop('id')}", json=next_client
        )
    return next_client


async def prune_platform_service_clients(
    realm_name: str,
    platform: api.Platform,
    all: bool = False,  # noqa: A002
):
    """
    Prunes clients for platform services.

    If all is True, all clients for the platform are pruned. If all is False, only
    clients for unrecognised services are pruned.
    """
    # List the clients that have the platform name in their client id
    response = await kc_client.get(
        f"/{realm_name}/clients", params={"q": platform.metadata.name}
    )
    for client in response.json():
        # Clients for the platform will have client IDs of the form {platform}.{service}
        if "." not in client["clientId"]:
            continue
        platform_name, service_name = client["clientId"].split(".", maxsplit=1)
        # Ignore clients for other platforms
        if platform_name != platform.metadata.name:
            continue
        # Ignore clients for services that we recognise when required
        if not all and service_name in platform.spec.zenith_services:
            continue
        # If the client is not for a recognised service, delete it
        LOGGER.info(
            "Deleting client for platform service '%s/%s' - %s",
            platform.metadata.name,
            service_name,
            realm_name,
        )
        await kc_client.delete(f"/{realm_name}/clients/{client['id']}")
