import typing as t

from pydantic import TypeAdapter, Field, AnyHttpUrl as PyAnyHttpUrl, conint, constr
from pydantic.functional_validators import AfterValidator

from configomatic import Configuration as BaseConfiguration, Section, LoggingConfiguration


#: Type for a string that validates as a URL
AnyHttpUrl = t.Annotated[
    str,
    AfterValidator(lambda v: str(TypeAdapter(PyAnyHttpUrl).validate_python(v)))
]


class SecretRef(Section):
    """
    A reference to a secret.
    """
    #: The name of the secret
    name: constr(min_length = 1)
    #: The namespace of the secret
    namespace: constr(min_length = 1)


class DexConfig(Section):
    """
    Configuration for the Dex instances that authenticate with Azimuth.
    """
    #: The Helm chart repo, name and version to use for Dex instances
    #: By default, this points to a local pull of the chart that is baked into the Docker image
    chart_name: constr(min_length = 1) = "/charts/dex"
    chart_repo: t.Optional[AnyHttpUrl] = None
    chart_version: t.Optional[constr(min_length = 1)] = None

    #: Default Helm values to merge with calculated values for Dex releases
    default_values: t.Dict[str, t.Any] = Field(default_factory = dict)

    #: The host to use for Dex instances
    #: The realm instances will be provisioned using subpaths on this host
    host: constr(min_length = 1)
    #: The template for generating prefixes for Dex instances
    #: This will have the Keycloak realm name and tenancy ID available to it
    prefix_template: constr(min_length = 1) = "/authproxy/{tenancy_id}"

    #: The name of the secret containing the TLS secret for the host
    #: If it is given, Dex instances will have TLS enabled
    tls_secret: t.Optional[SecretRef] = None

    #: The ingress class to use for ingress resources
    #: Note that only the NGINX ingress controller is currently supported
    ingress_class_name: constr(min_length = 1) = "nginx"
    #: The default annotations for the ingress resources
    ingress_default_annotations: t.Dict[str, str] = Field(default_factory = dict)
    #: The auth URL to use for the ingress auth subrequest
    ingress_auth_url: AnyHttpUrl
    #: The URL that unauthenticated users should be redirected to to sign in
    ingress_auth_signin_url: t.Optional[AnyHttpUrl] = None
    #: The HTTP parameter to put the next URL in when redirecting to sign in
    ingress_auth_signin_redirect_param: str = "next"

    #: The alias to use for the Keycloak client
    keycloak_client_alias: constr(min_length = 1) = "azimuth"
    #: The number of bytes to use for the client secret
    keycloak_client_secret_bytes: conint(gt = 0) = 64


def strip_trailing_slash(v: str) -> str:
    """
    Strips trailing slashes from the given string.
    """
    return v.rstrip("/")


class KeycloakConfig(Section):
    """
    Configuration for the target Keycloak instance.
    """
    #: The base URL of the Keycloak instance
    base_url: t.Annotated[AnyHttpUrl, AfterValidator(strip_trailing_slash)]

    #: The client ID to use when authenticating with Keycloak
    client_id: constr(min_length = 1)
    #: The realm that the client belongs to
    client_realm: constr(min_length = 1) = "master"
    #: The username and password to use when authenticating with Keycloak
    username: constr(min_length = 1)
    password: constr(min_length = 1)

    #: Indicates if SSL is required for external requests
    ssl_required: bool = True

    #: The scheme to use for Zenith redirect URIs
    zenith_redirect_uri_scheme: t.Literal["http", "https"] = "https"
    #: The path to use for Zenith redirect URIs
    zenith_redirect_uri_path: constr(min_length = 1) = "/_oidc/callback"
    #: The namespace to write Zenith discovery secrets into
    zenith_discovery_namespace: constr(min_length = 1) = "zenith-services"
    #: The template for generating the names of discovery secrets
    zenith_discovery_secret_name_template: constr(min_length = 1) = "oidc-discovery-{subdomain}"

    #: The alias of the first broker login flow that will be copied to make the flow
    source_first_login_flow_alias: constr(min_length = 1) = "first broker login"
    #: The alias of the target first login flow that will be copied to
    target_first_login_flow_alias: constr(min_length = 1) = "azimuth first login"
    #: The name of the review profile execution to disable
    review_profile_execution_name: constr(min_length = 1) = "idp-review-profile"

    #: The name to use for the admins group in each realm
    #: Members of this group get realm admin permissions
    admins_group_name: constr(min_length = 1) = "admins"
    #: The name to use for the platform users group in each realm
    #: Members of this group get access to all the platforms deployed in a project
    platform_users_group_name: constr(min_length = 1) = "platform-users"
    #: The client roles to ensure are present in the admins group
    #: The value is a mapping of client => list of roles for client
    admins_group_client_roles: t.Dict[str, t.List[str]] = Field(
        default_factory = lambda: { "realm-management": ["realm-admin"] }
    )


class HelmClientConfiguration(Section):
    """
    Configuration for the Helm client.
    """
    #: The default timeout to use with Helm releases
    #: Can be an integer number of seconds or a duration string like 5m, 5h
    default_timeout: t.Union[int, constr(min_length = 1)] = "5m"
    #: The executable to use
    #: By default, we assume Helm is on the PATH
    executable: constr(min_length = 1) = "helm"
    #: The maximum number of revisions to retain in the history of releases
    history_max_revisions: int = 10
    #: Indicates whether to verify TLS when pulling charts
    insecure_skip_tls_verify: bool = False
    #: The directory to use for unpacking charts
    #: By default, the system temporary directory is used
    unpack_directory: t.Optional[str] = None


class Configuration(
    BaseConfiguration,
    default_path = "/etc/azimuth/identity-operator.yaml",
    path_env_var = "AZIMUTH_IDENTITY_CONFIG",
    env_prefix = "AZIMUTH_IDENTITY"
):
    """
    Top-level configuration model.
    """
    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The API group of the cluster CRDs
    api_group: constr(min_length = 1) = "identity.azimuth.stackhpc.com"
    #: A list of categories to place CRDs into
    crd_categories: t.List[constr(min_length = 1)] = Field(
        default_factory = lambda: ["azimuth", "identity", "azimuth-identity"]
    )

    #: The field manager name to use for server-side apply
    easykube_field_manager: constr(min_length = 1) = "azimuth-identity-operator"

    #: The amount of time (seconds) before a watch is forcefully restarted
    watch_timeout: conint(gt = 0) = 600

    #: Configuration for Dex instances
    dex: DexConfig

    #: Configuration for Keycloak
    keycloak: KeycloakConfig

    #: The Helm client configuration
    helm_client: HelmClientConfiguration = Field(default_factory = HelmClientConfiguration)


settings = Configuration()
