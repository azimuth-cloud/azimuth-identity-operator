import logging

from . import client as kc_client


LOGGER = logging.getLogger(__name__)


async def ensure_group(realm_name: str, group_name: str):
    """
    Ensures that the specified group exists in Keycloak.
    """
    # Get the existing group, if one exists
    response = await kc_client.get(
        f"/{realm_name}/groups",
        params = {
            "briefRepresentation": "false",
            "q": group_name,
            "exact": "true",
        }
    )
    try:
        group = next(group for group in response.json() if group["name"] == group_name)
    except StopIteration:
        LOGGER.info("Creating group '%s' in realm - %s", group_name, realm_name)
        response = await kc_client.post(f"/{realm_name}/groups", json = { "name": group_name })
        # The Keycloak API does not return a representation in the create response,
        # but it does return the URL to get one in the location header
        response = await kc_client.get(response.headers["location"])
        group = response.json()
        group.pop("access", None)
    return group
