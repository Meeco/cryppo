# Cryppo Release Notes

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

Given a version number MAJOR.MINOR.PATCH, increment the:

MAJOR version when you make incompatible API changes
MINOR version when you add functionality in a backwards-compatible manner
PATCH version when you make backwards-compatible bug fixes

## Unreleased

### Fixed
* Fixed wrong number of arguments being passed to `EncryptionValues::EncryptedData` in `Cryppo.to_encrypted_data_value`

## [0.2.0] - 2018-10-04

### Changed
* `EnryptionStrategy` and  `KeyDerivationStrategy` names are now derived from the class name (excluding the module name)

### Fixed
* Errors of type `Cryppo::Error` raised during an encryption/decryption operation no longer get reraised as `EncryptionError` or `DecryptionError`.
  As an example, attempting to encrypt a `EncryptionValues::EncryptionKey` should raise a `CoercionOfEncryptedKeyToString` error, however, it was being converted to an `EncryptionError`

## [0.1.0] - 2018-10-04

### Added
* The initial implementation of the Cryppo lib.  Includes:
  * Encryption strategies:
    * Aes256Gcm
    * Aes256Ofb
    * Rsa4096
  * Key derivation strategies:
    * Pbkdf2Hmac
  * Wrapper objects:
    * DerivedKey
    * EncryptedData
    * EncryptedDataWithDerivedKey
    * EncryptionKey
  * Basic encryption and decryption implementations:
    * `Cryppo.encrypt`
    * `Cryppo.encrypt_with_derived_key`
    * `Cryppo.decrypt`
    * `Cryppo.decrypt_with_derived_key`
    * `Cryppo.generate_encryption_key`
  * Basic rspec tests
