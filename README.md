# Cryppo

Cryppo is a cryptographic library that enables you to encrypt and decrypt data.

Pick an encryption strategy and encrypt away!

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cryppo'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cryppo

## Usage

### Encrypt and decrypt data using a derived key

#### Encryption

When encrypting data with a user-generated passphrase or password, use the `encrypt_with_derived_key` function.

The data will be encrypted with cryptographically secure key that is derived from the passphrase.

```ruby
encryption_strategy = 'Aes256Gcm'
key_derivation_strategy = 'Pbkdf2Hmac'
user_passphrase = 'MyPassword!!'
data = 'some data to encrypt'
encrypted_data = Cryppo.encrypt_with_derived_key(encryption_strategy, key_derivation_strategy, user_passphrase, data)
```

#### Persisting Encrypted Data
The encryption process will return an `EncryptedDataWithDerivedKey` object that contains all the encryption artifacts necessary to decrypt the encrypted data.
The data in this object can be serialised using the the `EncryptedDataWithDerivedKey#serialise` method.
The serialised payload can be stored directly in a database.
The serialised payload can later be loaded by using `Cryppo.load(serialised_payload)`.

```ruby
serialised_payload = encrypted_data.serialise
loaded_encrypted_data = Cryppo.load(serialised_payload)
```

The older method of persistence required the following values be store:
* `encrypted_data.encryption_strategy.strategy_name`
* `encrypted_data.encrypted_data`
* `encrypted_data.encryption_artefacts`
* `encrypted_data.key_derivation_strategy.strategy_name`
* `encrypted_data.derivation_artefacts`

**Note: Never store the contents of objects of type `Cryppo::EncryptionValues::EncryptionKey`**.  These objects contain keys used to encrypt the data.  They should never be stored in the clear.  They need to be kept safe and protected!!

#### Decryption
To decrypt the encrypted data, we load the serialised encrypted data, and then decrypt with the users passphrase:

Following on from the encryption example:

```ruby
user_passphrase = 'MyPassword!!'
encrypted_data = Cryppo.load(serialised_payload)
encrypted_data.decrypt(user_passphrase)
```

##### The old decryption method
To decrypt the encrypted data, we need to combine all the artefacts produced during the encryption process along with the users passphrase.

Following on from the encryption example:

```ruby
user_passphrase = 'MyPassword!!'
encryption_strategy_name = encrypted_data.encryption_strategy.strategy_name
key_derivation_strategy_name = encrypted_data.key_derivation_strategy.strategy_name
encrypted_data = encrypted_data.encrypted_data
encryption_artefacts = encrypted_data.encryption_artefacts
derivation_artefacts = encrypted_data.derivation_artefacts

decrypted_data = Cryppo.decrypt_with_derived_key(encryption_strategy_name, key_derivation_strategy_name, user_passphrase, encrypted_data, encryption_artefacts, derivation_artefacts)
```

### Encrypt and decrypt data using a generated cryptographic key

If you need, you can also encrypt using your own generated key using the `generate_encryption_key` and the `encrypt` functions:

#### Encryption

```ruby
encryption_strategy = 'Aes256Gcm'
key = Cryppo.generate_encryption_key(encryption_strategy) # this key needs to be kept safe
data = 'some data to encrypt'
encrypted_data = Cryppo.encrypt(encryption_strategy, key, data)
```

#### Persisting Encrypted Data
The encryption process will return an `EncryptedData` object that contains all the encryption artefacts necessary to decrypt the encrypted data.
The data in this object can be serialised using the the `EncryptedData#serialise` method.
The serialised payload can be stored directly in a database.
The serialised payload can later be loaded by using `Cryppo.load(serialised_payload)`.

The older method of persistence required the following values be store:
* `encrypted_data.encryption_strategy.strategy_name`
* `encrypted_data.encrypted_data`
* `encrypted_data.encryption_artefacts`

**Note: Never store the contents of objects of type `Cryppo::EncryptionValues::EncryptionKey`**.  These objects contain keys used to encrypt the data.  They should never be stored in the clear.  They need to be kept safe and protected!!

#### Decryption

To decrypt the encrypted data, we load the serialised encrypted data, and then decrypt with the users passphrase:

Following on from the encryption example:

```ruby
encrypted_data = Cryppo.load(serialised_payload)
encrypted_data.decrypt(key)
```

##### The old decryption method

To decrypt the encrypted data, we need to combine all the artefacts produced during the encryption process along with the encryption key.

Following on from the encryption example:

```ruby
encryption_strategy_name = encrypted_data.encryption_strategy.strategy_name
encrypted_data = encrypted_data.encrypted_data
encryption_artefacts = encrypted_data.encryption_artefacts

decrypted_data = Cryppo.decrypt(encryption_strategy_name, key, encrypted_data, encryption_artefacts)
```

## Serialisation Format

The serialisation format of encrypted data is designed to be easy to parse and store.

There are two serialisation formats:
* Encrypted data encrypted without a derived key
* Encrypted data encrypted with a derived key

### Encrypted data encrypted without a derived key

A string containing 3 parts concatenated with a `.`.

1. Encryption Strategy Name: The stategy name as defined by EncryptionStrategy#strategy_name
2. Encoded Encrypted Data: Encrypted Data is encoded with Base64.urlsafe_encode64
3. Encoded Encryption Artefacts: Encryption Artefacts are serialised into a hash by EncryptionStrategy#serialise_artefact, converted to YAML, then encoded with Base64.urlsafe_encode64

### Encrypted data encrypted with a derived key

A string containing 5 parts concatenated with a `.`.  The first 3 parts are the same as above.

4. Key Derivation Strategy Name: The stategy name as defined by EncryptionStrategy#strategy_name
5. Encoded Key Derivation Artefacts: Encryption Artefacts are serialised into a hash by EncryptionStrategy#serialise_artefact, converted to YAML, then encoded with Base64.urlsafe_encode64

### Serialisation of encryption artefacts and key derivation artefacts

Each strategy is responsible for serialising and deserialising any artefacts it produces.
The goal is to produce a hash containing the artefacts required to decrypt the encrypted data.
The keys should be stringified to enhance compatibility between different YAML implementations.
The keys should optionally be abbreviated to reduce the serialised payload size.

## Encryption Strategies

The current strategies are wrappers around ruby's OpenSSL library.

### Aes256Ofb

Aes256Ofb was chosen because if the incorrect salt is used during decryption, the encrypted data will remain entirely encrypted.

### Aes256Gcm

Aes256Gcm was chosen because it provides authenticated encryption.  An error will be raised if an incorrect value, such as the encryption key, were used during decryption.  This means you can always be sure that the decrypted data is the same as the data that was originally encrypted.

## Key Derivation Strategies

The current key derivation strategies are wrappers around ruby's OpenSSL library.

### Pbkdf2Hmac

Pbkdf2Hmac generates cryptographically secure keys from potentially insecure sources such as user-generated passwords.

The derived key is cryptographically secure such that brute force attacks directly on the encrypted data is infeasible.
The amount of computational effort required to complete the operation can be tweaked. This ensures that brute force attacks on the password encrypted data.

## Wishlist

* [ ] Provide a way for third parties to register additional encryption strategies and key derivation strategies
* [ ] Tag encryption strategies that can accept derived keys.  Eg AES strategies can accept Pbkdf2 derived keys whereas Rsa4096 can only accept an OpenSSL::PKey::RSA as the encryption key.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Meeco/cryppo. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Code of Conduct

Everyone interacting in the Cryppo project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/Meeco/cryppo/blob/master/CODE_OF_CONDUCT.md).
