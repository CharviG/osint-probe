import os

from spiderfoot.sflib import SpiderFoot, SpiderFootEvent


ip_modules = [
    'sfp_abusech',
    'sfp_badipscom',
    'sfp_blocklistde',
    'sfp_cybercrimetracker',
    'sfp_dnsneighbor',
    'sfp_dronebl',
    'sfp_fortinet',
    'sfp_hosting',
    'sfp_isc',
    'sfp_malwaredomainlist',
    'sfp_multiproxy',
    'sfp_nothink',
    'sfp_portscan_tcp',
    'sfp_sorbs',
    'sfp_spamcop',
    'sfp_spamhaus',
    'sfp_threatcrowd',
    'sfp_torexits',
    'sfp_torserver',
    'sfp_uceprotect',
    'sfp_voipbl',
    'sfp_vxvault',
    'sfp_watchguard',
    'sfp_robtex',
    'sfp_botscout'
]


class IP:

    def __init__(self):
        self.sf = SpiderFoot()
        self.root_event = SpiderFootEvent('ROOT', '', 'sfp_root', 'ROOT')

    def probe(self, ip_address):
        self.sf.clear_results()

        curr_path = os.path.dirname(__file__)
        for filename in os.listdir(curr_path + '/modules/'):
            if filename.startswith("sfp_") and filename.endswith(".py"):
                mod_name = filename.split('.')[0]

                mod = __import__('spiderfoot.modules.' + mod_name, globals(), locals(), [mod_name])
                _cls = getattr(mod, mod_name)

                self.call_module(_cls, mod_name, ip_address)

        return self.sf.get_results()

    def call_module(self, module_class, module_name, target):

        m = module_class()
        m.__name__ = module_name

        event = SpiderFootEvent('IP_ADDRESS', target, module_name, self.root_event)
        m.setup(self.sf, {
            '_fetchtimeout': 50,
            '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
            '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0'
        })

        m.handleEvent(event)
