from pydantic import Field

from kube_custom_resource import CustomResource, schema


class RealmSpec(schema.BaseModel):
    """
    The spec for an Azimuth identity realm.
    """
    tenancy_id: schema.constr(min_length = 1) = Field(
        ...,
        description = "The ID of the Azimuth tenancy that the realm is for."
    )


class RealmPhase(str, schema.Enum):
    """
    The possible phases for a realm.
    """
    UNKNOWN  = "Unknown"
    PENDING  = "Pending"
    READY    = "Ready"
    DELETING = "Deleting"
    FAILED   = "Failed"


class RealmStatus(schema.BaseModel, extra = "allow"):
    """
    The status of an Azimuth identity realm.
    """
    phase: RealmPhase = Field(
        RealmPhase.UNKNOWN.value,
        description = "The phase of the realm."
    )
    oidc_issuer_url: schema.Optional[schema.AnyHttpUrl] = Field(
        None,
        description = "The OIDC issuer URL for the realm."
    )
    admin_url: schema.Optional[schema.AnyHttpUrl] = Field(
        None,
        description = "The admin URL for the realm."
    )
    failure_message: str = Field(
        "",
        description = "The reason that the realm entered the failed phase, if known."
    )


class Realm(
    CustomResource,
    subresources = {"status": {}},
    printer_columns = [
        {
            "name": "Phase",
            "type": "string",
            "jsonPath": ".status.phase",
        },
        {
            "name": "Tenancy ID",
            "type": "string",
            "jsonPath": ".spec.tenancyId",
        },
        {
            "name": "OIDC issuer",
            "type": "string",
            "jsonPath": ".status.oidcIssuerUrl",
        },
    ]
):
    """
    An Azimuth identity realm.
    """
    spec: RealmSpec
    status: RealmStatus = Field(default_factory = RealmStatus)
