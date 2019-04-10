# OSINT PROBE

The purpose of this module is to modify spiderfoot modules to be run specifically rather than in discovery mode.

The end goals are:
 
 * To use run spiderfoot modules on a particular type of event
 * Use spiderfoot modules with minimal code changes.
 * Python 3 compatibility
 * Design a core modules that can be plugged in easily. 

## Installation

    pip install git+https://github.com/ajoyoommen/osint-probe.git


## Usage

    from osint_probe import Probe

    ip_probe = Probe('IP_ADDRESS', {
        'IP_REPUTATION': ['sfp_abusech.py']
    })

    ip_probe.run('192.168.1.1', 'IP_REPUTATION')

