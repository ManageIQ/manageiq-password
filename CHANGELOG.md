# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

## [1.1.0] - 2021-11-08
### Added
- Add manageiq-password CLI [[#23](https://github.com/ManageIQ/manageiq-password/pull/23)]

### Fixed
- chmod v2_key on creation [[#22](https://github.com/ManageIQ/manageiq-password/pull/22)]
- Raise an exception when decrypting plaintext [[#26](https://github.com/ManageIQ/manageiq-password/pull/26)]
- Fix encrypted? and try_decrypt to work with erb strings [[#28](https://github.com/ManageIQ/manageiq-password/pull/28)]

## [1.0.0] - 2021-05-05
### Removed
- **BREAKING**: Drop support for legacy v0 and v1 keys [[#14](https://github.com/ManageIQ/manageiq-password/pull/14)]
- **BREAKING**: Drop add_legacy_key and related methods [[#15](https://github.com/ManageIQ/manageiq-password/pull/15)]
  - Legacy key support via recrypt should now pass the legacy key to the recrypt
    method as a parameter, as ManageIQ::Password will no longer store the legacy
    key
- **BREAKING**: Drop deprecated methods [[#16](https://github.com/ManageIQ/manageiq-password/pull/16)]

[Unreleased]: https://github.com/ManageIQ/more_core_extensions/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/ManageIQ/more_core_extensions/compare/v1.1.0...v1.0.0
[1.0.0]: https://github.com/ManageIQ/more_core_extensions/compare/v1.0.0...v0.3.0
