import typing as t

from pydantic import Field

from kube_custom_resource import CustomResource, schema


class OIDCClientGrantType(str, schema.Enum):
    """
    The supported OIDC grant types.

    https://oauth.net/2/grant-types/
    """
    AUTHORIZATION_CODE = "AuthorizationCode"
    CLIENT_CREDENTIALS = "ClientCredentials"
    DEVICE_CODE = "DeviceCode"


class OIDCClientSpec(schema.BaseModel):
    """
    The spec for an OIDC client.
    """
    realm_name: schema.constr(min_length = 1) = Field(
        ...,
        description = "The name of the realm to create the client in."
    )
    client_id: schema.Optional[schema.constr(min_length = 1)] = Field(
        None,
        description = "The client ID to use. If not given, the name is used."
    )
    public: bool = Field(
        False,
        description = (
            "Indicates if the client is a public client. "
            "Public clients are not able to keep a client secret safe."
        )
    )
    grant_types: t.List[OIDCClientGrantType] = Field(
        default_factory = list,
        description = "The grant types to allow for the client."
    )
    redirect_uris: t.List[schema.AnyHttpUrl] = Field(
        default_factory = list,
        description = "The redirect URIs for the client."
    )
    credentials_secret_name: schema.Optional[schema.constr(min_length = 1)] = Field(
        None,
        description = "The name of the secret into which client credentials should be written."
    )


class OIDCClientPhase(str, schema.Enum):
    """
    The possible phases for an OIDC client.
    """
    UNKNOWN  = "Unknown"
    PENDING  = "Pending"
    UPDATING = "Updating"
    READY    = "Ready"
    DELETING = "Deleting"
    FAILED   = "Failed"


class OIDCClientStatus(schema.BaseModel, extra = "allow"):
    """
    The status of an OIDC client.
    """
    phase: OIDCClientPhase = Field(
        OIDCClientPhase.UNKNOWN.value,
        description = "The phase of the OIDC client."
    )
    issuer_url: schema.Optional[schema.constr(min_length = 1)] = Field(
        None,
        description = "The issuer URL for the OIDC client."
    )
    client_id: schema.Optional[schema.constr(min_length = 1)] = Field(
        None,
        description = "The client ID of the OIDC client."
    )
    credentials_secret_name: schema.Optional[schema.constr(min_length = 1)] = Field(
        None,
        description = "The name of the secret into which client credentials are written."
    )


class OIDCClient(
    CustomResource,
    subresources = {"status": {}},
    printer_columns = [
        {
            "name": "Realm",
            "type": "string",
            "jsonPath": ".spec.realmName",
        },
        {
            "name": "Public",
            "type": "boolean",
            "jsonPath": ".spec.public",
        },
        {
            "name": "Grant Types",
            "type": "string",
            "jsonPath": ".spec.grantTypes",
        },
        {
            "name": "Phase",
            "type": "string",
            "jsonPath": ".status.phase",
        },
        {
            "name": "Client ID",
            "type": "string",
            "jsonPath": ".status.clientId",
        },
        {
            "name": "Credentials Secret",
            "type": "string",
            "jsonPath": ".status.credentialsSecretName",
        },
    ]
):
    """
    An OIDCClient.
    """
    spec: OIDCClientSpec = Field(default_factory = OIDCClientSpec)
    status: OIDCClientStatus = Field(default_factory = OIDCClientStatus)
