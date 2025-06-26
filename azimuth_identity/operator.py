import asyncio
import functools
import json
import logging
import sys

import kopf

from easykube import Configuration, ApiError
from kube_custom_resource import CustomResourceRegistry

from . import dex, keycloak, models
from .config import settings
from .models import v1alpha1 as api


LOGGER = logging.getLogger(__name__)


# Create an easykube client from the environment
from pydantic.json import pydantic_encoder
ekconfig = Configuration.from_environment(json_encoder = pydantic_encoder)
ekclient = ekconfig.async_client(default_field_manager = settings.easykube_field_manager)


# Create a registry of custom resources and populate it from the models module
registry = CustomResourceRegistry(settings.api_group, settings.crd_categories)
registry.discover_models(models)


@kopf.on.startup()
async def apply_settings(**kwargs):
    """
    Apply kopf settings.
    """
    kopf_settings = kwargs["settings"]
    kopf_settings.persistence.finalizer = f"{settings.api_group}/finalizer"
    kopf_settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix = settings.api_group
    )
    kopf_settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix = settings.api_group,
        key = "last-handled-configuration",
    )
    kopf_settings.watching.client_timeout = settings.watch_timeout
    # Apply the CRDs
    for crd in registry:
        try:
            await ekclient.apply_object(crd.kubernetes_resource(), force = True)
        except Exception:
            LOGGER.exception("error applying CRD %s.%s - exiting", crd.plural_name, crd.api_group)
            sys.exit(1)
    # Give Kubernetes a chance to create the APIs for the CRDs
    await asyncio.sleep(0.5)
    # Check to see if the APIs for the CRDs are up
    # If they are not, the kopf watches will not start properly so we exit and get restarted
    LOGGER.info("Waiting for CRDs to become available")
    for crd in registry:
        preferred_version = next(k for k, v in crd.versions.items() if v.storage)
        api_version = f"{crd.api_group}/{preferred_version}"
        try:
            _ = await ekclient.get(f"/apis/{api_version}/{crd.plural_name}")
        except Exception:
            LOGGER.exception(
                "api for %s.%s not available - exiting",
                crd.plural_name,
                crd.api_group
            )
            sys.exit(1)
    await keycloak.client.init()


@kopf.on.cleanup()
async def on_cleanup(**kwargs):
    """
    Runs on operator shutdown.
    """
    LOGGER.info("Closing Kubernetes and Keycloak clients")
    await ekclient.aclose()
    await keycloak.client.close()


def format_instance(instance):
    """
    Formats an instance for logging.
    """
    if instance.metadata.name == instance.metadata.namespace:
        return instance.metadata.name
    else:
        return f"{instance.metadata.namespace}/{instance.metadata.name}"


async def ekresource_for_model(model, subresource = None):
    """
    Returns an easykube resource for the given model.
    """
    api = ekclient.api(f"{settings.api_group}/{model._meta.version}")
    resource = model._meta.plural_name
    if subresource:
        resource = f"{resource}/{subresource}"
    return await api.resource(resource)


async def save_instance_status(instance):
    """
    Save the status of the given instance.
    """
    ekresource = await ekresource_for_model(type(instance), "status")
    data = await ekresource.replace(
        instance.metadata.name,
        {
            # Include the resource version for optimistic concurrency
            "metadata": { "resourceVersion": instance.metadata.resource_version },
            "status": instance.status.model_dump(exclude_defaults = True),
        },
        namespace = instance.metadata.namespace
    )
    # Store the new resource version
    instance.metadata.resource_version = data["metadata"]["resourceVersion"]


def model_handler(model, register_fn, **kwargs):
    """
    Decorator that registers a handler with kopf for the specified model.
    """
    api_version = f"{settings.api_group}/{model._meta.version}"
    def decorator(func):
        @functools.wraps(func)
        async def handler(**handler_kwargs):
            if "instance" not in handler_kwargs:
                handler_kwargs["instance"] = model.model_validate(handler_kwargs["body"])
            try:
                return await func(**handler_kwargs)
            except ApiError as exc:
                if exc.status_code == 409:
                    # When a handler fails with a 409, we want to retry quickly
                    raise kopf.TemporaryError(str(exc), delay = 5)
                else:
                    raise
        return register_fn(api_version, model._meta.plural_name, **kwargs)(handler)
    return decorator


@model_handler(api.Realm, kopf.on.create)
@model_handler(api.Realm, kopf.on.update, field = "spec")
@model_handler(api.Realm, kopf.on.resume)
async def reconcile_realm(instance: api.Realm, **kwargs):
    """
    Handles the reconciliation of a realm.
    """
    if instance.status.phase == api.RealmPhase.UNKNOWN:
        instance.status.phase = api.RealmPhase.PENDING
        LOGGER.info("Updating realm status to PENDING - %s", format_instance(instance))
        await save_instance_status(instance)
    # Derive the realm name from the realm instance
    realm_name = keycloak.realm.realm_name(instance)
    # Create the realm
    await keycloak.realm.ensure_realm(realm_name)
    # Create the groups scope
    await keycloak.realm.ensure_groups_scope(instance, realm_name)
    # If required, configure the realm as a tenancy realm
    # If not, just leave it as a vanilla realm
    if instance.spec.tenancy_id:
        # Ensure that the Dex instance for the realm exists
        dex_client = await dex.ensure_realm_instance(ekclient, instance, realm_name)
        # Make sure that the profile requirements for the realm are set up correctly
        await keycloak.realm.ensure_user_profile_config(realm_name)
        # Create and wire up the admins and platform users group
        await keycloak.realm.ensure_admins_group(realm_name)
        await keycloak.realm.ensure_platform_users_group(realm_name)
        # Create and wire up the identity provider for Dex
        await keycloak.realm.ensure_identity_provider(instance, realm_name, dex_client)
    instance.status.phase = api.RealmPhase.READY
    instance.status.oidc_issuer_url = f"{settings.keycloak.base_url}/realms/{realm_name}"
    instance.status.admin_url = f"{settings.keycloak.base_url}/admin/{realm_name}/console"
    # Keycloak group names are prefixed with a slash
    instance.status.platform_users_group = (
        f"/{settings.keycloak.platform_users_group_name}"
        if instance.spec.tenancy_id
        else None
    )
    LOGGER.info("Realm reconciled successfully, saving status - %s", format_instance(instance))
    await save_instance_status(instance)


@model_handler(api.Realm, kopf.on.delete)
async def delete_realm(instance: api.Realm, **kwargs):
    """
    Handes the deletion of a realm.
    """
    if instance.status.phase != api.RealmPhase.DELETING:
        instance.status.phase = api.RealmPhase.DELETING
        LOGGER.info("Updating realm status to DELETING - %s", format_instance(instance))
        await save_instance_status(instance)
    # Delete the Dex instance
    await dex.delete_realm_instance(instance)
    # Remove the realm from Keycloak
    realm_name = keycloak.realm.realm_name(instance)
    await keycloak.realm.remove_realm(realm_name)
    LOGGER.info("Realm deleted successfully - %s", format_instance(instance))


async def get_realm(name: str, namespace: str) -> api.Realm:
    """
    Fetch the specified realm, or None if it doesn't exist.
    """
    ekrealms = await ekresource_for_model(api.Realm)
    try:
        realm = await ekrealms.fetch(name, namespace = namespace)
    except ApiError as exc:
        if exc.status_code == 404:
            return
        else:
            raise
    else:
        return api.Realm.model_validate(realm)


async def wait_for_realm(name: str, namespace: str) -> api.Realm:
    """
    Fetch the specified realm and wait for it to become ready.
    """
    realm = await get_realm(name, namespace)
    if not realm:
        raise kopf.TemporaryError(f"Realm '{namespace}/{name}' does not exist", delay = 10)
    if realm.status.phase != api.RealmPhase.READY:
        raise kopf.TemporaryError(f"Realm '{namespace}/{name}' is not ready", delay = 10)
    return realm


@model_handler(api.OIDCClient, kopf.on.create, param = "CREATE")
@model_handler(api.OIDCClient, kopf.on.update, field = "spec", param = "UPDATE")
@model_handler(api.OIDCClient, kopf.on.resume, param = "RESUME")
async def reconcile_oidc_client(instance: api.OIDCClient, param, **kwargs):
    """
    Handles the reconciliation of an OIDC client.
    """
    # Acknowledge the client at the earliest opportunity
    if instance.status.phase == api.OIDCClientPhase.UNKNOWN:
        instance.status.phase = api.OIDCClientPhase.PENDING
        LOGGER.info("Updating OIDC client status to PENDING - %s", format_instance(instance))
        await save_instance_status(instance)
    # If the spec has changed, put the client into the updating phase
    if param == "UPDATE" and instance.status.phase != api.OIDCClientPhase.UPDATING:
        instance.status.phase = api.OIDCClientPhase.UPDATING
        LOGGER.info("Updating OIDC client status to UPDATING - %s", format_instance(instance))
        await save_instance_status(instance)
    # Get the realm for the client and wait for it to become ready
    LOGGER.info("Fetching realm for OIDC client - %s", format_instance(instance))
    realm = await wait_for_realm(instance.spec.realm_name, instance.metadata.namespace)
    realm_name = keycloak.realm.realm_name(realm)
    client_id, client_secret = await keycloak.oidc_client.ensure_oidc_client(realm_name, instance)
    # If the client has a secret, write the client ID and secret to a Kubernetes secret
    # If the client does NOT have a secret, delete the Kubernetes secret
    # The OIDC client owns the secret so it gets deleted when the client does
    secrets = await ekclient.api("v1").resource("secrets")
    secret_name = (
        instance.spec.credentials_secret_name or
        f"{instance.metadata.name}-oidc-credentials"
    )
    if client_secret:
        await secrets.server_side_apply(
            secret_name,
            {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/managed-by": "azimuth-identity-operator",
                    },
                    "ownerReferences": [
                        {
                            "apiVersion": instance.api_version,
                            "kind": instance.kind,
                            "name": instance.metadata.name,
                            "uid": instance.metadata.uid,
                            "controller": True,
                            "blockOwnerDeletion": True,
                        },
                    ],
                },
                "stringData": {
                    "issuer-url": realm.status.oidc_issuer_url,
                    "client-id": client_id,
                    "client-secret": client_secret,
                },
            },
            namespace = instance.metadata.namespace,
            force = True
        )
    else:
        await secrets.delete(secret_name, namespace = instance.metadata.namespace)
    # Update the status to say we are ready
    instance.status.phase = api.OIDCClientPhase.READY
    instance.status.issuer_url = realm.status.oidc_issuer_url
    instance.status.client_id = client_id
    instance.status.credentials_secret_name = secret_name if client_secret else None
    await save_instance_status(instance)


@model_handler(api.OIDCClient, kopf.on.delete)
async def delete_oidc_client(instance: api.OIDCClient, **kwargs):
    """
    Handles the deletion of an OIDC client.
    """
    if instance.status.phase != api.OIDCClientPhase.DELETING:
        instance.status.phase = api.OIDCClientPhase.DELETING
        LOGGER.info("Updating OIDC client status to DELETING - %s", format_instance(instance))
        await save_instance_status(instance)
    # Get the realm for the client
    LOGGER.info("Fetching realm for OIDC client - %s", format_instance(instance))
    realm = await get_realm(instance.spec.realm_name, instance.metadata.namespace)
    # If the realm doesn't exist, we assume that the OIDC client is gone
    if not realm:
        LOGGER.warning("Realm does not exist for OIDC client - %s", format_instance(instance))
        return
    # Remove the OIDC client from Keycloak
    realm_name = keycloak.realm.realm_name(realm)
    await keycloak.oidc_client.remove_oidc_client(realm_name, instance)
    LOGGER.info("OIDC client deleted successfully - %s", format_instance(instance))


@model_handler(api.Platform, kopf.on.create, param = "CREATE")
@model_handler(api.Platform, kopf.on.update, field = "spec", param = "UPDATE")
@model_handler(api.Platform, kopf.on.resume, param = "RESUME")
async def reconcile_platform(instance: api.Platform, param, **kwargs):
    """
    Handles the reconciliation of a platform.
    """
    # Acknowledge the platform at the earliest opportunity
    if instance.status.phase == api.PlatformPhase.UNKNOWN:
        instance.status.phase = api.PlatformPhase.PENDING
        LOGGER.info("Updating platform status to PENDING - %s", format_instance(instance))
        await save_instance_status(instance)
    # If the spec has changed, put the platform into the updating phase
    if param == "UPDATE":
        instance.status.phase = api.PlatformPhase.UPDATING
        LOGGER.info("Updating platform status to UPDATING - %s", format_instance(instance))
        await save_instance_status(instance)
    # First, get the realm for the platform and wait for it to become ready
    LOGGER.info("Fetching realm for platform - %s", format_instance(instance))
    realm = await wait_for_realm(instance.spec.realm_name, instance.metadata.namespace)
    realm_name = keycloak.realm.realm_name(realm)
    # Create a group for the platform
    # Because realms and platforms are both namespace-scoped, we know that the the
    # platform name will be unique within the realm
    group = await keycloak.platform.ensure_platform_group(realm_name, instance)
    # For each Zenith service, ensure that a client exists and update the discovery secret
    for service_name, service in instance.spec.zenith_services.items():
        # Create a subgroup
        subgroup = await keycloak.platform.ensure_platform_service_subgroup(
            realm_name,
            group,
            service_name
        )
        # Create a client
        client = await keycloak.platform.ensure_platform_service_client(
            realm_name,
            instance,
            service_name,
            service
        )
        # Write discovery information for Zenith
        LOGGER.info(
            "Creating/updating Zenith OIDC discovery secret - %s/%s",
            format_instance(instance),
            service_name
        )
        # Calculate the allowed groups
        allowed_groups = [
            # Allow the parent group for the platform
            group["path"],
            # Allow users to be added to a subgroup for the specific service
            subgroup["path"],
        ]
        # Add the platform users group if the realm has one
        if realm.status.platform_users_group:
            allowed_groups.insert(0, realm.status.platform_users_group)
        await ekclient.apply_object(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": settings.keycloak.zenith_discovery_secret_name_template.format(
                        subdomain = service.subdomain
                    ),
                    "namespace": settings.keycloak.zenith_discovery_namespace,
                    "labels": {
                        "app.kubernetes.io/managed-by": "azimuth-identity-operator",
                        f"{settings.api_group}/platform-namespace": instance.metadata.namespace,
                        f"{settings.api_group}/platform-name": instance.metadata.name,
                        f"{settings.api_group}/service-name": service_name,
                        f"{settings.api_group}/subdomain": service.subdomain,
                    },
                },
                "stringData": {
                    "issuer-url": realm.status.oidc_issuer_url,
                    "client-id": client["clientId"],
                    "client-secret": client["secret"],
                    "allowed-groups": json.dumps(allowed_groups),
                },
            },
            force = True
        )
    # Delete all the Zenith discovery secrets belonging to this platform that
    # correspond to subdomains that we no longer recognise
    known_subdomains = { s.subdomain for s in instance.spec.zenith_services.values() }
    eksecrets = await ekclient.api("v1").resource("secrets")
    async for secret in eksecrets.list(
        labels = {
            "app.kubernetes.io/managed-by": "azimuth-identity-operator",
            f"{settings.api_group}/platform-namespace": instance.metadata.namespace,
            f"{settings.api_group}/platform-name": instance.metadata.name,
        },
        namespace = settings.keycloak.zenith_discovery_namespace
    ):
        secret_subdomain = secret.metadata.labels[f"{settings.api_group}/subdomain"]
        if secret_subdomain not in known_subdomains:
            LOGGER.info(
                "Pruning Zenith discovery secret for unrecognised service - %s/%s",
                format_instance(instance),
                secret.metadata.labels[f"{settings.api_group}/service-name"]
            )
            await eksecrets.delete(
                secret.metadata.name,
                namespace = secret.metadata.namespace
            )
    # Delete all the clients belonging to services that we no longer recognise
    await keycloak.platform.prune_platform_service_clients(realm_name, instance)
    # Delete all the subgroups belonging to services that we no longer recognise
    await keycloak.platform.prune_platform_service_subgroups(realm_name, instance, group)
    instance.status.phase = api.PlatformPhase.READY
    LOGGER.info("Platform reconciled successfully, saving status - %s", format_instance(instance))
    await save_instance_status(instance)


@model_handler(api.Platform, kopf.on.delete)
async def delete_platform(instance: api.Platform, **kwargs):
    """
    Handles the deletion of a platform.
    """
    if instance.status.phase != api.PlatformPhase.DELETING:
        instance.status.phase = api.PlatformPhase.DELETING
        LOGGER.info("Updating platform status to DELETING - %s", format_instance(instance))
        await save_instance_status(instance)
    # First, delete the Zenith discovery secrets
    LOGGER.info("Deleting Zenith discovery secrets - %s", format_instance(instance))
    secrets = await ekclient.api("v1").resource("secrets")
    await secrets.delete_all(
        labels = {
            "app.kubernetes.io/managed-by": "azimuth-identity-operator",
            f"{settings.api_group}/platform-namespace": instance.metadata.namespace,
            f"{settings.api_group}/platform-name": instance.metadata.name,
        },
        namespace = settings.keycloak.zenith_discovery_namespace
    )
    # Get the realm for the platform
    LOGGER.info("Fetching realm for platform - %s", format_instance(instance))
    realm = await get_realm(instance.spec.realm_name, instance.metadata.namespace)
    # If the realm doesn't exist, we assume that the Keycloak resources are gone
    if not realm:
        LOGGER.warning("Realm does not exist for platform - %s", format_instance(instance))
        return
    realm_name = keycloak.realm.realm_name(realm)
    # Remove the clients for all the services
    await keycloak.platform.prune_platform_service_clients(realm_name, instance, all = True)
    # Remove the platform group
    await keycloak.platform.remove_platform_group(realm_name, instance)


@kopf.daemon(
    "v1",
    "secrets",
    labels = { f"{settings.api_group}/tls-secret": kopf.PRESENT },
    cancellation_timeout = 1
)
async def reconcile_tls_secret(name, namespace, **kwargs):
    """
    Reconciles the secret by copying the configured TLS secret.
    """
    if not settings.dex.tls_secret:
        return
    # Daemons get their own client to avoid choking the connection pool
    client = ekconfig.async_client(default_field_manager = settings.easykube_field_manager)
    async with client:
        secrets = await client.api("v1").resource("secrets")
        LOGGER.info(
            "Watching TLS secret for changes - %s/%s",
            settings.dex.tls_secret.namespace,
            settings.dex.tls_secret.name
        )
        initial, events = await secrets.watch_one(
            settings.dex.tls_secret.name,
            namespace = settings.dex.tls_secret.namespace
        )
        if initial:
            LOGGER.info("Patching TLS mirror secret - %s/%s", namespace, name)
            _ = await secrets.patch(
                name,
                { "data": initial["data"] },
                namespace = namespace
            )
        async for event in events:
            # Ignore delete events and just leave the secret in place
            if event["type"] == "DELETED":
                return
            if "object" in event:
                LOGGER.info("Patching TLS mirror secret - %s/%s", namespace, name)
                _ = await secrets.patch(
                    name,
                    { "data": event["object"]["data"] },
                    namespace = namespace
                )
