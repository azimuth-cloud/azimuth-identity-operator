"""Tests for the Dex ingress sign-in redirect."""

import typing as t

import pytest

from azimuth_identity import dex
from azimuth_identity.config import settings
from azimuth_identity.models import v1alpha1 as api

SIGNIN_URL = "https://portal.example.com/auth/login"
NEXT_URL = "$scheme://$best_http_host$escaped_request_uri"


class FakeEasykubeClient:
    """Record the objects that would be applied to Kubernetes."""

    def __init__(self) -> None:
        """Start with no applied objects."""
        self.applied: dict[str, dict[str, t.Any]] = {}

    async def apply_object(
        self, obj: dict[str, t.Any], force: bool = False
    ) -> dict[str, t.Any]:
        """Record the object by name and return it."""
        self.applied[obj["metadata"]["name"]] = obj
        return obj


async def test_auth_ingress_embeds_signin_redirect_param(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check that the sign-in URL carries next= and no redirect-param annotation.

    Traefik's Ingress NGINX provider ignores auth-signin-redirect-param.
    """
    monkeypatch.setattr(settings.dex, "ingress_auth_signin_url", SIGNIN_URL)
    realm = api.Realm.model_validate(
        {
            "apiVersion": f"{settings.api_group}/v1alpha1",
            "kind": "Realm",
            "metadata": {"name": "az-demo", "namespace": "az-demo", "uid": "1"},
            "spec": {"tenancy_id": "tenancy-1"},
        }
    )
    ekclient = FakeEasykubeClient()

    await dex.ensure_ingresses(ekclient, realm, "az-demo")

    annotations = ekclient.applied["az-demo-dex-auth"]["metadata"]["annotations"]
    assert (
        annotations["nginx.ingress.kubernetes.io/auth-signin"]
        == f"{SIGNIN_URL}?next={NEXT_URL}"
    )
    assert "nginx.ingress.kubernetes.io/auth-signin-redirect-param" not in annotations


def test_auth_signin_url_appends_to_existing_query_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check that the redirect parameter is added to an existing query string."""
    monkeypatch.setattr(
        settings.dex, "ingress_auth_signin_url", f"{SIGNIN_URL}?foo=bar"
    )

    assert dex.auth_signin_url() == f"{SIGNIN_URL}?foo=bar&next={NEXT_URL}"
