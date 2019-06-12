# Change Log
This document lists changes made to the OSINT Probe for each recorded release.

## [3.1.0] - 12/06/2019
### Added
- Added sfp_cryptocurrency for querying popular cryptocurrency blockchains.
- Added CHANGELOG file

### Removed
- Removed sfp_blockchain

## [3.0.0] - 16/04/2019
### Added
- Python 3 compatibility
- Added sfp_accounts, sfp_haveibeenpwned, sfp_pgp, sfp_wikileaks
- Added Probe class to use modules on a particular event
- Added setup file

### Changed
- Modified sflib to run modules on particular events
- Modified sf modules to be compatibile with new sflib

### Removed
- Non-core libraries and unused helpers