import unittest
from unittest import mock

from azimuth_identity.operator import operator


class TestOperator(unittest.IsolatedAsyncioTestCase):
    @mock.patch("azimuth_identity.operator.settings")
    @mock.patch("azimuth_identity.operator.ekclient.api", new_callable=mock.AsyncMock)
    async def test_ekresource_for_model(self, mock_api, mock_settings):
        mock_model = mock.MagicMock()
        mock_model._meta.version = "vFake"
        mock_model._meta.plural_name = "fakeplural"

        mock_settings.api_group = "fake.group"

        mock_resource = mock.AsyncMock()
        mock_api.return_value.resource.return_value = mock_resource

        result = await operator.ekresource_for_model(mock_model)

        mock_api.assert_awaited_once_with("fake.group/vFake")
        mock_api.return_value.resource.assert_awaited_once_with("fakeplural")
        self.assertEqual(result, mock_resource)

    @mock.patch("azimuth_identity.operator.settings")
    @mock.patch("azimuth_identity.operator.ekclient.api", new_callable=mock.AsyncMock)
    async def test_ekresource_for_model_with_subresource(self, mock_api, mock_settings):
        mock_model = mock.MagicMock()
        mock_model._meta.version = "vOther"
        mock_model._meta.plural_name = "otherplural"

        mock_settings.api_group = "another.group"

        mock_resource = mock.AsyncMock()
        mock_api.return_value.resource.return_value = mock_resource

        result = await operator.ekresource_for_model(mock_model, subresource="status")

        mock_api.assert_awaited_once_with("another.group/vOther")
        mock_api.return_value.resource.assert_awaited_once_with("otherplural/status")
        self.assertEqual(result, mock_resource)
