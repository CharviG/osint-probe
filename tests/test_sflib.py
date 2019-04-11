import unittest

from sflib import SpiderFoot, SpiderFootEvent, SpiderFootPlugin


class DummySFPlugin(SpiderFootPlugin):
    def setup(self, sfc, **kwargs):
        self.sf = sfc

    def handleEvent(self, sfEvent):
        event = SpiderFootEvent('Result', 'message', self.__name__, sfEvent)
        self.notifyListeners(event)


class TestSpiderfootBases(unittest.TestCase):
    def test_plugin_handle_event(self):
        sf = SpiderFoot()
        root_event = SpiderFootEvent('ROOT', '', 'sfp_root', 'ROOT')

        sfp = DummySFPlugin()
        sfp.__name__ = 'TestSFPlugin'

        event = SpiderFootEvent('Custom event', 'target', 'TestSFPlugin', root_event)
        sfp.setup(sf)

        sfp.handleEvent(event)

        results = sf.get_results()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['data'], 'message')
