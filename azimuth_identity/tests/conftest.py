"""Set the minimum configuration required to import the operator modules."""

import os

# The operator settings are loaded when azimuth_identity.config is first imported
os.environ.update(
    {
        "AZIMUTH_IDENTITY__DEX__HOST": "dex.example.com",
        "AZIMUTH_IDENTITY__DEX__INGRESS_AUTH_URL": "http://azimuth-api/verify/",
        "AZIMUTH_IDENTITY__KEYCLOAK__BASE_URL": "http://keycloak.example.com",
        "AZIMUTH_IDENTITY__KEYCLOAK__CLIENT_ID": "admin-cli",
        "AZIMUTH_IDENTITY__KEYCLOAK__USERNAME": "admin",
        "AZIMUTH_IDENTITY__KEYCLOAK__PASSWORD": "password",
    }
)
