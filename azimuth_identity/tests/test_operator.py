import unittest
from unittest import mock

from azimuth_identity import operator

class TestOperator(unittest.IsolatedAsyncioTestCase):
    def test_name_equals_namespace(self):
        instance = MockInstance(name="example", namespace="example")
        self.assertEqual(format_instance(instance), "example")

    def test_name_differs_from_namespace(self):
        instance = MockInstance(name="my-service", namespace="platform-1")
        self.assertEqual(format_instance(instance), "platform-1/my-service")
