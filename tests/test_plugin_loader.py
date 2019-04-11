import unittest

from sflib import SpiderFoot, SpiderFootEvent, SpiderFootPlugin
from osint_probe import Probe


class TestPluginLoader(unittest.TestCase):
    def test_plugin_loaded(self):
        test_event_probe = Probe('TEST_EVENT', {
            'TEST_EVENT': ['test_plugin']
        })

        data = test_event_probe.run('target', scan_type='TEST_EVENT')
        self.assertEqual(data, [])
