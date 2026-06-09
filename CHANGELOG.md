# Changelog

## NetSniper v1.3

NetSniper v1.3 improves exposure accuracy, reduces false positives, and strengthens compatibility with TrueAegis validation workflows.

### Added

* `PORTAINER_CANDIDATE` findings for services detected on TCP ports `9000` and `9443`
* Evidence messages explaining when Portainer fingerprint validation is required
* Improved compatibility with the TrueAegis v1.1 structured validation engine
* More accurate downstream handling of services that share commonly reused ports

### Changed

* Open TCP ports `9000` and `9443` are no longer automatically treated as confirmed Portainer exposures
* Hosts are no longer classified as container infrastructure solely because TCP ports `9000` or `9443` are open
* Container-infrastructure classification now relies on stronger Docker-oriented signals such as TCP ports `2375` and `2376`
* Portainer-related findings now remain candidates until protocol and product fingerprinting confirms the service
* Scanner version updated to `v1.3`

### Improved

* Reduced false positives caused by cameras, management interfaces, and unrelated applications using TCP port `9000`
* More accurate device classification
* Cleaner risk scoring for downstream analysis
* Better interoperability with TrueAegis service validation and remediation reporting

### Notes

NetSniper remains a standalone network reconnaissance and exposure-intelligence engine. TrueAegis integration is optional and provides additional validation, remediation guidance, and reporting capabilities.

NetSniper is intended for authorized security assessments only. Use the tool only on systems and networks where you have explicit permission.
