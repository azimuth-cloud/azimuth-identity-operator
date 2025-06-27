import copy
import json
import logging

import httpx

from .. import dex  # noqa: TID252
from ..config import settings  # noqa: TID252
from ..models import v1alpha1 as api  # noqa: TID252
from . import client as kc_client
from .group import ensure_group

LOGGER = logging.getLogger(__name__)


def realm_name(realm: api.Realm):
    """
    Returns the Keycloak realm name for the given realm.
    """
    # If the realm name is an exact match for the namespace, dedupe it
    # This is the only thing we can do while guaranteeing uniqueness
    if realm.metadata.name == realm.metadata.namespace:
        return realm.metadata.name
    else:
        return f"{realm.metadata.namespace}-{realm.metadata.name}"


async def ensure_realm(realm_name: str):
    """
    Ensures that the specified Keycloak realm exists and is enabled.
    """
    # First, ensure that a realm with the given name exists
    LOGGER.info("Creating realm if not exists - %s", realm_name)
    try:
        await kc_client.post("/", json={"realm": realm_name})
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code != 409:
            raise
    response = await kc_client.get(f"/{realm_name}")
    realm = response.json()
    realm_original = realm.copy()
    # Ensure the realm is enabled
    realm["enabled"] = True
    # Ensure that SSL is required or not as per the settings
    realm["sslRequired"] = "external" if settings.keycloak.ssl_required else "none"
    # Patch the realm if needed
    if realm != realm_original:
        LOGGER.info("Updating realm configuration - %s", realm_name)
        await kc_client.put(f"/{realm_name}", json=realm)


async def remove_realm(realm_name: str):
    """
    Ensures that the specified Keycloak realm is removed.
    """
    LOGGER.info("Deleting realm - %s", realm_name)
    try:
        await kc_client.delete(f"/{realm_name}")
    except httpx.HTTPStatusError as exc:
        # Not found is fine - it means the realm doesn't exist
        if exc.response.status_code != 404:
            raise


async def ensure_groups_scope(realm: api.Realm, realm_name: str):
    """
    Ensures that a groups scope exists that provides the user's groups.
    """
    # Get the existing groups scope, if it exists
    response = await kc_client.get(f"/{realm_name}/client-scopes")
    existing_scope = next(
        (scope for scope in response.json() if scope["name"] == "groups"), {}
    )
    # Update the scope as required
    scope = copy.deepcopy(existing_scope)
    scope.update(
        {
            "name": "groups",
            "description": "Group memberships",
            "protocol": "openid-connect",
        }
    )
    # Create or update the scope in Keycloak
    if not existing_scope:
        LOGGER.info("Creating groups scope for OIDC clients - %s", realm_name)
        response = await kc_client.post(f"/{realm_name}/client-scopes", json=scope)
        response = await kc_client.get(response.headers["location"])
        scope = response.json()
    elif scope != existing_scope:
        LOGGER.info("Updating groups scope for OIDC clients - %s", realm_name)
        await kc_client.put(f"/{realm_name}/client-scopes/{scope['id']}", json=scope)
    # Ensure that the scope is in the realm default scopes
    # To do this properly, we must first make sure it is not optional
    response = await kc_client.get(f"/{realm_name}/default-optional-client-scopes")
    if any(s["id"] == scope["id"] for s in response.json()):
        LOGGER.info(
            "Removing groups scope from optional client scopes - %s", realm_name
        )
        await kc_client.delete(
            f"/{realm_name}/default-optional-client-scopes/{scope['id']}"
        )
    # This fails with a conflict if the scope is already a default or optional scope,
    # but we know from above that the scope is not optional, so the 409 is OK
    LOGGER.info("Adding groups scope to default client scopes - %s", realm_name)
    try:
        await kc_client.put(
            f"/{realm_name}/default-default-client-scopes/{scope['id']}"
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code != 409:
            raise
    # Make sure that the scope has the protocol mapper for mapping groups
    try:
        existing_mapper = next(
            pm for pm in scope.get("protocolMappers", []) if pm["name"] == "groups"
        )
    except StopIteration:
        existing_mapper = {}
    protocol_mapper = copy.deepcopy(existing_mapper)
    protocol_mapper.update(
        {
            "name": "groups",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-group-membership-mapper",
        }
    )
    protocol_mapper.setdefault("config", {}).update(
        {
            "claim.name": "groups",
            "full.path": "true",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        }
    )
    protocol_mappers_base = (
        f"/{realm_name}/client-scopes/{scope['id']}/protocol-mappers/models"
    )
    if not existing_mapper:
        LOGGER.info("Create protocol mapper for groups scope - %s", realm_name)
        await kc_client.post(protocol_mappers_base, json=protocol_mapper)
    elif protocol_mapper != existing_mapper:
        LOGGER.info("Updating protocol mapper for groups scope - %s", realm_name)
        await kc_client.put(
            f"{protocol_mappers_base}/{protocol_mapper['id']}", json=protocol_mapper
        )


async def ensure_user_profile_config(realm_name: str):
    """
    Ensures that the user profile for the realm is set up correctly.

    In particular, we don't want firstName and lastName to be required.
    """
    # The user profile is enabled by default from Keycloak 24.0.0
    # On older versions, this instead looks for a user with ID "profile", which will
    # never exist
    response = await kc_client.get(f"/{realm_name}/users/profile")
    if response.status_code != 200:
        LOGGER.info("User profile not supported, skipping config - %s", realm_name)
        return
    profile = response.json()
    profile_original = copy.deepcopy(profile)
    # Update the profile to make username the only required field
    profile["attributes"] = [
        {k: v for k, v in attr.items() if k != "required"}
        for attr in profile["attributes"]
        # We will add the desired state of the federatedId attribute after
        if attr["name"] != "federatedId"
    ]
    profile["attributes"].append(
        {
            "name": "federatedId",
            "displayName": "Federated ID",
            "validations": {
                "length": {
                    "max": 255,
                },
                "up-username-not-idn-homograph": {},
            },
            "annotations": {},
            "permissions": {"view": ["admin", "user"], "edit": []},
            "multivalued": False,
        }
    )
    # Patch the profile if required
    if profile != profile_original:
        LOGGER.info("Updating user profile configuration - %s", realm_name)
        await kc_client.put(f"/{realm_name}/users/profile", json=profile)


async def ensure_admins_group(realm_name: str):
    """
    Ensures that the Keycloak admins group is set up and has the required roles.
    """
    # Get or create the group
    group = await ensure_group(realm_name, settings.keycloak.admins_group_name)
    # Make sure that the group has all the client roles that are configured
    # We need to turn client names into IDs, so load all the clients and index them
    response = await kc_client.get(f"/{realm_name}/clients")
    client_ids = {client["clientId"]: client["id"] for client in response.json()}
    for client_name, roles in settings.keycloak.admins_group_client_roles.items():
        existing_roles = group.get("clientRoles", {}).get(client_name, [])
        missing_roles = [role for role in roles if role not in existing_roles]
        if missing_roles:
            client_id = client_ids[client_name]
            # We need to get the ID for each role, so load the available client roles
            # and index them
            response = await kc_client.get(
                f"/{realm_name}/groups/{group['id']}/"
                f"role-mappings/clients/{client_id}/available"
            )
            role_ids = {role["name"]: role["id"] for role in response.json()}
            LOGGER.info(
                "Updating role mappings for client '%s' in admins group - %s",
                client_name,
                realm_name,
            )
            await kc_client.post(
                f"/{realm_name}/groups/{group['id']}/role-mappings/clients/{client_id}",
                json=[{"id": role_ids[role], "name": role} for role in missing_roles],
            )


async def ensure_platform_users_group(realm_name: str):
    """
    Ensures that the platform users group is set up in Keycloak.
    """
    # Get or create the group
    await ensure_group(realm_name, settings.keycloak.platform_users_group_name)


async def ensure_identity_provider(realm: api.Realm, realm_name, dex_client):
    """
    Ensures that a Keycloak identity provider exists for Azimuth for the given realm.
    """
    idp_url = (
        f"/{realm_name}/identity-provider/"
        f"instances/{settings.dex.keycloak_client_alias}"
    )
    # Get the existing IDP as a starting base
    try:
        response = await kc_client.get(idp_url)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            existing_idp = {}
        else:
            raise
    else:
        existing_idp = response.json()
    # Update with what we think the IDP should look like
    next_idp = copy.deepcopy(existing_idp)
    next_idp.update(
        {
            "providerId": "oidc",
            "enabled": True,
            "alias": settings.dex.keycloak_client_alias,
            "displayName": "Azimuth",
            # Ensure that the IDP is using our first login flow
            "firstBrokerLoginFlowAlias": await _ensure_idp_first_login_flow(
                realm, realm_name
            ),
        }
    )
    issuer = "{scheme}://{host}{prefix}".format(
        scheme="https" if settings.dex.tls_secret else "http",
        host=settings.dex.host,
        prefix=dex.path_prefix(realm, realm_name),
    )
    next_idp.setdefault("config", {}).update(
        {
            "issuer": issuer,
            "authorizationUrl": f"{issuer}/auth",
            "tokenUrl": f"{issuer}/token",
            "userInfoUrl": f"{issuer}/userinfo",
            "useJwksUrl": "true",
            "validateSignature": "true",
            "jwksUrl": f"{issuer}/keys",
            "clientAuthMethod": "client_secret_post",
            "clientId": dex_client["id"],
            "clientSecret": dex_client["secret"],
            "syncMode": "IMPORT",
            "defaultScope": "openid profile email groups federated:id",
        }
    )
    # Update the identity provider in Keycloak if required
    if not existing_idp:
        LOGGER.info("Creating Azimuth IdP - %s", realm_name)
        await kc_client.post(
            f"/{realm_name}/identity-provider/instances", json=next_idp
        )
    elif existing_idp != next_idp:
        LOGGER.info("Updating Azimuth IdP - %s", realm_name)
        await kc_client.put(idp_url, json=next_idp)
    # Ensure that the mappers are properly configured
    await _ensure_idp_group_mapper(
        realm, idp_url, "realm-admin", settings.keycloak.admins_group_name
    )
    await _ensure_idp_group_mapper(
        realm, idp_url, "platform-user", settings.keycloak.platform_users_group_name
    )
    await _ensure_idp_federated_id_mapper(realm, idp_url)


async def _ensure_idp_first_login_flow(realm: api.Realm, realm_name: str):
    """
    Ensures that the first login flow for the IDP exists and that the review profile
    execution is disabled.
    """
    # First, try to find the review profile execution for the flow
    executions_url = "/{}/authentication/flows/{}/executions".format(
        realm_name, settings.keycloak.target_first_login_flow_alias
    )
    try:
        response = await kc_client.get(executions_url)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code != 404:
            raise
        # If the executions don't exist, we need to create the flow by copying the
        # source flow
        LOGGER.info(
            "Copying flow '%s' for Azimuth IdP - %s",
            settings.keycloak.source_first_login_flow_alias,
            realm_name,
        )
        await kc_client.post(
            "/{}/authentication/flows/{}/copy".format(
                realm_name, settings.keycloak.source_first_login_flow_alias
            ),
            json={"newName": settings.keycloak.target_first_login_flow_alias},
        )
        return await _ensure_idp_first_login_flow(realm, realm_name)
    else:
        existing_execution = next(
            execution
            for execution in response.json()
            if execution["providerId"]
            == settings.keycloak.review_profile_execution_name
        )
    next_execution = copy.deepcopy(existing_execution)
    next_execution["requirement"] = "DISABLED"
    if existing_execution != next_execution:
        LOGGER.info("Updating flow executions for Azimuth IdP - %s", realm_name)
        await kc_client.put(executions_url, json=next_execution)
    return settings.keycloak.target_first_login_flow_alias


async def _ensure_idp_group_mapper(
    realm: api.Realm, idp_url: str, mapper_name: str, group_name: str
):
    """
    Ensures that the IDP has a mapper that puts users into the specified group.
    """
    # Get the existing realm-admins mapper
    response = await kc_client.get(f"{idp_url}/mappers")
    try:
        existing_mapper = next(
            mapper for mapper in response.json() if mapper["name"] == mapper_name
        )
    except StopIteration:
        existing_mapper = {}
    # Update with what the mapper should look like
    next_mapper = copy.deepcopy(existing_mapper)
    next_mapper.update(
        {
            "name": mapper_name,
            "identityProviderAlias": settings.dex.keycloak_client_alias,
            "identityProviderMapper": "oidc-advanced-group-idp-mapper",
        }
    )
    next_mapper.setdefault("config", {}).update(
        {
            "claims": json.dumps(
                [
                    {
                        "key": "groups",
                        "value": realm.spec.tenancy_id,
                    },
                ]
            ),
            "syncMode": "FORCE",
            "are.claim.values.regex": "false",
            "group": f"/{group_name}",
        }
    )
    # Update the mapper in Keycloak if required
    if not existing_mapper:
        LOGGER.info(
            "Creating group mapper for '%s' - %s", group_name, realm_name(realm)
        )
        await kc_client.post(f"{idp_url}/mappers", json=next_mapper)
    elif existing_mapper != next_mapper:
        LOGGER.info(
            "Updating group mapper for '%s' - %s", group_name, realm_name(realm)
        )
        await kc_client.put(
            f"{idp_url}/mappers/{existing_mapper['id']}", json=next_mapper
        )


async def _ensure_idp_federated_id_mapper(realm: api.Realm, idp_url: str):
    """
    Ensures that the IDP has a mapper that sets an attribute with the federated ID.
    """
    # Get the existing realm-admins mapper
    response = await kc_client.get(f"{idp_url}/mappers")
    try:
        existing_mapper = next(
            mapper for mapper in response.json() if mapper["name"] == "federated-id"
        )
    except StopIteration:
        existing_mapper = {}
    # Update with what the mapper should look like
    next_mapper = copy.deepcopy(existing_mapper)
    next_mapper.update(
        {
            "name": "federated-id",
            "identityProviderAlias": settings.dex.keycloak_client_alias,
            "identityProviderMapper": "oidc-user-attribute-idp-mapper",
        }
    )
    next_mapper.setdefault("config", {}).update(
        {
            "claim": "federated_claims.user_id",
            "user.attribute": "federatedId",
            "syncMode": "FORCE",
        }
    )
    # Update the mapper in Keycloak if required
    if not existing_mapper:
        LOGGER.info("Creating federated ID mapper - %s", realm_name(realm))
        await kc_client.post(f"{idp_url}/mappers", json=next_mapper)
    elif existing_mapper != next_mapper:
        LOGGER.info("Updating federated ID mapper - %s", realm_name(realm))
        await kc_client.put(
            f"{idp_url}/mappers/{existing_mapper['id']}", json=next_mapper
        )
