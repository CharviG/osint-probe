import os
from uuid import uuid4

from sflib import SpiderFoot, SpiderFootEvent


class ProbeManager:
    def __init__(self):
        self.probes = dict()

    def new_probe(self, data):
        uuid = str(uuid4())
        self.probes[uuid] = dict(
            query=data,
            results=[],
            status='STARTED'
        )
        return uuid

    def get_probe(self, uuid):
        return self.probes[uuid]

    def update_probe(self, uuid, results):
        if type(results) == list:
            self.probes[uuid]['results'].extend(results)
        else:
            raise Exception('List is required')


class Probe:
    def __init__(self, entity_type, modules, calling_module=None):
        self.sf = SpiderFoot()
        self.root_event = SpiderFootEvent('ROOT', '', 'sfp_root', 'ROOT')
        self.event_type = entity_type
        self.modules = modules

        self.calling_module = calling_module

    def run(self, target, scan_type):
        self.sf.clear_results()

        module_list = self.modules[scan_type]
        curr_path = os.path.dirname(__file__)

        for _module in module_list:
            if _module not in os.listdir(curr_path + '\\sfp_modules\\'):
                continue

            mod_name = _module.split('.')[0]

            mod = __import__('sfp_modules.' + mod_name, globals(), locals(), [mod_name])
            _cls = getattr(mod, mod_name)
            self.call_module(_cls, mod_name, target)
        return self.sf.get_results()

    def call_module(self, module_class, module_name, target):

        m = module_class()
        m.__name__ = module_name
        m.setTarget(target)

        calling_module = self.calling_module if self.calling_module else module_name
        event = SpiderFootEvent(self.event_type, target, calling_module, self.root_event)

        m.setup(self.sf, {
            '_fetchtimeout': 50,
            '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
            '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0'
        })

        m.handleEvent(event)


event_probe = Probe('IP_ADDRESS', [])