# OSINT PROBE

The purpose of this module is to modify Spiderfoot's modules to be run specifically rather than in discovery mode.

The end goals are:
 
 * To invoke Spiderfoot modules on a particular type of event
 * Integrate Spiderfoot modules with minimal code changes.
 * Python 3 compatibility
 * Design core modules that can be used to plug-in Spiderfoot modules easily.

## Installation

    pip install git+https://github.com/ajoyoommen/osint-probe.git


## Usage

* Import Probe

        from osint_probe import Probe

* Create a Probe for any particular event, Eg: IP_ADDRESS

        ip_probe = Probe('IP_ADDRESS', {
            'IP_REPUTATION': ['sfp_abusech.py']
        })

        ip_probe.run('192.168.1.1', 'IP_REPUTATION')

* Probe for CRYPTOCURRENCY events

        crypto_probe = Probe("CRYPTOCURRENCY_ADDRESS", {
            "CRYPTOCURRENCY_ADDRESS": ["sfp_cryptocurrency.py"]}, 'OSINT')
        crypto_probe.run("13usM2ns3f466LP65EY1h8hnTBLFiJV6rD", "CRYPTOCURRENCY_ADDRESS")
