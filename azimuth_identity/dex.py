import base64
import hashlib
import logging
import secrets
import typing as t

import kopf
import yaml

import easykube
import pyhelm3

from .config import settings
from .models import v1alpha1 as api


LOGGER = logging.getLogger(__name__)


def format_realm(realm: api.Realm):
    """
    Formats a realm for a log record.
    """
    if realm.metadata.name == realm.metadata.namespace:
        return realm.metadata.name
    else:
        return f"{realm.metadata.namespace}/{realm.metadata.name}"


def path_prefix(realm: api.Realm, keycloak_realm_name: str):
    """
    Returns the URL prefix for the Dex instance for the realm.
    """
    return settings.dex.prefix_template.format(
        realm_name = keycloak_realm_name,
        tenancy_id = realm.spec.tenancy_id
    )


async def ensure_tls_secret(ekclient, realm: api.Realm):
    """
    Ensures that a TLS secret exists for the Dex instance for the realm.

    Returns the TLS secret name.
    """
    # We make the secret as empty, but give it the label that triggers mirroring
    secret_name = f"{realm.metadata.name}-tls"
    secret_data = {
        "metadata": {
            "name": secret_name,
            "labels": {
                "app.kubernetes.io/managed-by": "azimuth-identity-operator",
                f"{settings.api_group}/tls-secret": "",
            },
        },
    }
    kopf.adopt(secret_data, realm.model_dump())
    eksecrets = await ekclient.api("v1").resource("secrets")
    LOGGER.info("Creating/updating TLS secret - %s", format_realm(realm))
    _ = await eksecrets.create_or_patch(
        secret_name,
        secret_data,
        namespace = realm.metadata.namespace
    )
    return secret_name


async def ensure_config_secret(
    ekclient,
    realm: api.Realm,
    keycloak_realm_name: str,
    tls_enabled: bool
):
    """
    Ensures that a Dex config secret exists for the realm.

    Returns the secret name, the config checksum and the client specification.
    """
    secret_name = f"{realm.metadata.name}-dex-conf"
    eksecrets = await ekclient.api("v1").resource("secrets")
    try:
        secret = await eksecrets.fetch(secret_name, namespace = realm.metadata.namespace)
    except easykube.ApiError as exc:
        if exc.status_code == 404:
            LOGGER.info("No existing Dex config - %s", format_realm(realm))
            existing_config = {}
        else:
            raise
    else:
        LOGGER.info("Found existing Dex config - %s", format_realm(realm))
        existing_config = yaml.safe_load(base64.b64decode(secret.data["config.yaml"]).decode())
    # Get the existing client secret, if there is one
    try:
        client_secret = existing_config["staticClients"][0]["secret"]
    except (KeyError, IndexError):
        LOGGER.info("Generating client secret for Keycloak - %s", format_realm(realm))
        client_secret = secrets.token_urlsafe(settings.dex.keycloak_client_secret_bytes)
    else:
        LOGGER.info("Using existing client secret for Keycloak - %s", format_realm(realm))
    # Build the OIDC client config for Keycloak
    client = {
        "name": "Keycloak",
        "redirectURIs": [
            "{base_url}/realms/{realm}/broker/{alias}/endpoint".format(
                base_url = settings.keycloak.base_url,
                realm = keycloak_realm_name,
                alias = settings.dex.keycloak_client_alias
            ),
        ],
        "id": "keycloak-oidc",
        "secret": client_secret,
    }
    # Build the full configuration
    next_config = {
        "issuer": "{scheme}://{host}{prefix}".format(
            scheme = "https" if tls_enabled else "http",
            host = settings.dex.host,
            prefix = path_prefix(realm, keycloak_realm_name)
        ),
        "oauth2": {
            "skipApprovalScreen": True,
        },
        "storage": {
            "type": "kubernetes",
            "config": {
                "inCluster": True,
            },
        },
        "connectors": [
            {
                "type": "authproxy",
                "id": "azimuth",
                "name": "Azimuth",
                "config": {
                    "userIdHeader": "X-Remote-User-Id",
                    "userHeader": "X-Remote-User",
                    "emailHeader": "X-Remote-User-Email",
                    "groupHeader": "X-Remote-Group",
                },
            },
        ],
        "staticClients": [client],
    }
    # Patch the secret if required
    if next_config != existing_config:
        secret_data = {
            "metadata": {
                "name": secret_name,
                "labels": {
                    "app.kubernetes.io/managed-by": "azimuth-identity-operator",
                },
            },
            "stringData": {
                "config.yaml": yaml.safe_dump(next_config),
            },
        }
        kopf.adopt(secret_data, realm.model_dump())
        LOGGER.info("Creating/updating Dex config secret - %s", format_realm(realm))
        _ = await eksecrets.create_or_patch(
            secret_name,
            secret_data,
            namespace = realm.metadata.namespace
        )
    config_hash = hashlib.sha256(yaml.safe_dump(next_config).encode())
    return secret_name, config_hash.hexdigest(), client


async def ensure_ingresses(
    ekclient,
    realm: api.Realm,
    keycloak_realm_name: str,
    tls_secret_name: t.Optional[str] = None
):
    """
    Ensures that the ingress resources exist for Dex for the given realm.
    """
    # Calculate the prefix that we will use for Dex instances
    # We need two ingresses for each Dex instance
    # One is unauthenticated and is used for the catchall path
    # The other is authenticated and is used for the authproxy callback path
    ingress_data = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": f"{realm.metadata.name}-dex",
            "namespace": realm.metadata.namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "azimuth-identity-operator",
            },
            "annotations": {
                **settings.dex.ingress_default_annotations,
                # Explicitly remove the x-remote-user from the request
                "nginx.ingress.kubernetes.io/configuration-snippet": (
                    "proxy_set_header X-Remote-User \"\";"
                ),
            },
        },
        "spec": {
            "ingressClassName": settings.dex.ingress_class_name,
            "tls": (
                [
                    {
                        "hosts": [settings.dex.host],
                        "secretName": tls_secret_name,
                    },
                ]
                if tls_secret_name
                else []
            ),
            "rules": [
                {
                    "host": settings.dex.host,
                    "http": {
                        "paths": [
                            {
                                "path": path_prefix(realm, keycloak_realm_name),
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": f"{realm.metadata.name}-dex",
                                        "port": {
                                            "name": "http",
                                        },
                                    },
                                },
                            },
                        ],
                    },
                },
            ],
        },
    }
    kopf.adopt(ingress_data, realm.model_dump())
    LOGGER.info("Creating main ingress for Dex - %s", format_realm(realm))
    _ = await ekclient.apply_object(ingress_data, force = True)
    auth_annotations = {
        "nginx.ingress.kubernetes.io/auth-url": settings.dex.ingress_auth_url,
        # Include the tenancy ID as a header for the auth request
        # This means that only users that belong to the tenancy will be considered authenticated
        "nginx.ingress.kubernetes.io/auth-snippet": (
            f"proxy_set_header X-Auth-Tenancy-Id \"{realm.spec.tenancy_id}\";"
        ),
        # Forward the X-Remote-{User-Id,User,User-Email,Group} headers from the auth response to the upstream
        "nginx.ingress.kubernetes.io/auth-response-headers": ",".join([
            "X-Remote-User-Id",
            "X-Remote-User",
            "X-Remote-User-Email",
            "X-Remote-Group",
        ])
    }
    if settings.dex.ingress_auth_signin_url:
        auth_annotations.update({
            "nginx.ingress.kubernetes.io/auth-signin": settings.dex.ingress_auth_signin_url,
            "nginx.ingress.kubernetes.io/auth-signin-redirect-param": (
                settings.dex.ingress_auth_signin_redirect_param
            ),
        })
    ingress_data = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": f"{realm.metadata.name}-dex-auth",
            "namespace": realm.metadata.namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "azimuth-identity-operator",
            },
            "annotations": {
                **settings.dex.ingress_default_annotations,
                **auth_annotations,
            }
        },
        "spec": {
            "ingressClassName": settings.dex.ingress_class_name,
            "tls": (
                [
                    {
                        "hosts": [settings.dex.host],
                        "secretName": tls_secret_name,
                    },
                ]
                if tls_secret_name
                else []
            ),
            "rules": [
                {
                    "host": settings.dex.host,
                    "http": {
                        "paths": [
                            {
                                "path": f"{path_prefix(realm, keycloak_realm_name)}/callback/azimuth",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": f"{realm.metadata.name}-dex",
                                        "port": {
                                            "name": "http",
                                        },
                                    },
                                },
                            },
                        ],
                    },
                },
            ],
        },
    }
    kopf.adopt(ingress_data, realm.model_dump())
    LOGGER.info("Creating authenticated ingress for Dex callback - %s", format_realm(realm))
    _ = await ekclient.apply_object(ingress_data, force = True)


async def ensure_realm_instance(ekclient, realm: api.Realm, keycloak_realm_name: str):
    """
    Ensures that a Dex instance exists for the realm.
    """
    # Configure the TLS certificate for Dex
    if settings.dex.tls_secret:
        tls_secret_name = await ensure_tls_secret(ekclient, realm)
    else:
        tls_secret_name = None
    # Generate the Dex configuration
    conf_secret_name, conf_checksum, kc_client = await ensure_config_secret(
        ekclient,
        realm,
        keycloak_realm_name,
        tls_secret_name is not None
    )
    # Create the Dex instance for the realm
    helm_client = pyhelm3.Client(
        default_timeout = settings.helm_client.default_timeout,
        executable = settings.helm_client.executable,
        history_max_revisions = settings.helm_client.history_max_revisions,
        insecure_skip_tls_verify = settings.helm_client.insecure_skip_tls_verify,
        unpack_directory = settings.helm_client.unpack_directory
    )
    LOGGER.info("Installing Dex release - %s", format_realm(realm))
    await helm_client.ensure_release(
        f"{realm.metadata.name}-dex",
        await helm_client.get_chart(
            settings.dex.chart_name,
            repo = settings.dex.chart_repo,
            version = settings.dex.chart_version
        ),
        settings.dex.default_values,
        {
            "configSecret": {
                "create": False,
                "name": conf_secret_name,
            },
            "podAnnotations": {
                "checksum/config": conf_checksum,
            },
        },
        namespace = realm.metadata.namespace,
        # The target namespace already exists, because the realm is in it
        create_namespace = False
    )
    # Generate the ingresses for Dex
    await ensure_ingresses(ekclient, realm, keycloak_realm_name, tls_secret_name)
    # Return the client to use with Keycloak
    return kc_client


async def delete_realm_instance(realm: api.Realm):
    """
    Deletes the Dex instance for a realm.

    We rely on owner references to delete secrets and ingresses.
    """
    # Delete the Dex release for the realm
    helm_client = pyhelm3.Client(
        default_timeout = settings.helm_client.default_timeout,
        executable = settings.helm_client.executable,
        history_max_revisions = settings.helm_client.history_max_revisions,
        insecure_skip_tls_verify = settings.helm_client.insecure_skip_tls_verify,
        unpack_directory = settings.helm_client.unpack_directory
    )
    LOGGER.info("Deleting Dex release - %s", format_realm(realm))
    _ = await helm_client.uninstall_release(
        f"{realm.metadata.name}-dex",
        namespace = realm.metadata.namespace
    )
