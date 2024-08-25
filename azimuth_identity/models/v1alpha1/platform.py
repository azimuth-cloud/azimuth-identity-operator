import typing as t

from pydantic import Field

from kube_custom_resource import CustomResource, schema


class ZenithServiceSpec(schema.BaseModel):
    """
    The spec for a Zenith service.
    """
    subdomain: schema.constr(pattern = r"[a-z0-9]+") = Field(
        ...,
        description = "The subdomain of the Zenith service."
    )
    fqdn: schema.constr(pattern = r"[a-z0-9\.-]+") = Field(
        ...,
        description = "The FQDN of the Zenith service."
    )


class PlatformSpec(schema.BaseModel):
    """
    The spec for an Azimuth identity platform.
    """
    realm_name: schema.constr(pattern = r"[a-z0-9-]+") = Field(
        ...,
        description = "The name of the realm that the platform belongs to."
    )
    zenith_services: t.Optional[schema.Dict[str, ZenithServiceSpec]] = Field(
        default_factory = dict,
        description = (
            "Map of name to subdomain and FQDN for Zenith services belonging to the platform."
        )
    )


class PlatformPhase(str, schema.Enum):
    """
    The possible phases for a realm.
    """
    UNKNOWN  = "Unknown"
    PENDING  = "Pending"
    UPDATING = "Updating"
    READY    = "Ready"
    DELETING = "Deleting"
    FAILED   = "Failed"


class PlatformStatus(schema.BaseModel, extra = "allow"):
    """
    The status of an Azimuth identity platform.
    """
    phase: PlatformPhase = Field(
        PlatformPhase.UNKNOWN.value,
        description = "The phase of the platform."
    )


class Platform(
    CustomResource,
    subresources = {"status": {}},
    printer_columns = [
        {
            "name": "Phase",
            "type": "string",
            "jsonPath": ".status.phase",
        },
    ]
):
    """
    An Azimuth identity platform.
    """
    spec: PlatformSpec
    status: PlatformStatus = Field(default_factory = PlatformStatus)
