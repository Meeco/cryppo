require 'yaml'
require 'base64'

module Cryppo
  extend self # adds instance methods as module methods.

  Error = Class.new(StandardError)
  UnsupportedEncryptionStrategy = Class.new(Error)
  UnsupportedKeyDerivationStrategy = Class.new(Error)
  CoercionOfEncryptedKeyToString = Class.new(Error)

  module EncryptionStrategies
    autoload :EncryptionStrategy, 'cryppo/encryption_strategies/encryption_strategy'
    autoload :AesStrategy, 'cryppo/encryption_strategies/aes_strategy'
    autoload :Aes256Ofb, 'cryppo/encryption_strategies/aes256_ofb'
    autoload :Aes256Gcm, 'cryppo/encryption_strategies/aes256_gcm'
    autoload :Rsa4096, 'cryppo/encryption_strategies/rsa4096'

    def self.by_name(strategy_name)
      const_get(strategy_name)
    rescue NameError => e
      raise UnsupportedEncryptionStrategy, e.message
    end
  end

  module EncryptionValues
    autoload :DerivedKey, 'cryppo/encryption_values/derived_key'
    autoload :EncryptedDataWithDerivedKey, 'cryppo/encryption_values/encrypted_data_with_derived_key'
    autoload :EncryptedData, 'cryppo/encryption_values/encrypted_data'
    autoload :EncryptionKey, 'cryppo/encryption_values/encryption_key'
  end

  module KeyDerivationStrategies
    autoload :KeyDerivationStrategy, 'cryppo/key_derivation_strategies/key_derivation_strategy'
    autoload :Pbkdf2Hmac, 'cryppo/key_derivation_strategies/pbkdf2_hmac'

    def self.by_name(strategy_name)
      const_get(strategy_name)
    rescue NameError => e
      raise UnsupportedKeyDerivationStrategy, e.message
    end
  end

  extend EncryptionValues::EncryptionKey::Helpers

  def encryption_strategy_by_name(strategy_name)
    EncryptionStrategies.by_name(strategy_name)
  end

  def key_derivation_strategy_by_name(strategy_name)
    KeyDerivationStrategies.by_name(strategy_name)
  end

  def encrypt(encryption_strategy_name, key, data)
    encryption_strategy = encryption_strategy_by_name(encryption_strategy_name).new
    encryption_strategy.encrypt(key, data)
  end

  def encrypt_with_derived_key(encryption_strategy_name, key_derivation_strategy_name, key, data)
    key_derivation_strategy = key_derivation_strategy_by_name(key_derivation_strategy_name).new
    derived_key_value = key_derivation_strategy.generate_derived_key(key)
    derived_key = derived_key_value.derived_key
    encrypted_data_value = encrypt(encryption_strategy_name, derived_key, data)
    EncryptionValues::EncryptedDataWithDerivedKey.new(encrypted_data_value, derived_key_value)
  end

  def to_encrypted_data_value(encryption_strategy_name, encrypted_data, **encryption_artefacts)
    encryption_strategy = encryption_strategy_by_name(encryption_strategy_name).new
    EncryptionValues::EncryptedData.new(encryption_strategy, encrypted_data, **encryption_artefacts)
  end

  def to_derived_key_value(key_derivation_strategy_name, **derivation_artefacts)
    key_derivation_strategy = key_derivation_strategy_by_name(key_derivation_strategy_name).new
    EncryptionValues::DerivedKey.new(key_derivation_strategy, nil, **derivation_artefacts)
  end

  def decrypt(encryption_strategy_name, key, encrypted_data, encryption_artefacts)
    encrypted_data = to_encrypted_data_value(encryption_strategy_name, encrypted_data, **encryption_artefacts)
    encrypted_data.decrypt(key)
  end

  def decrypt_with_derived_key(encryption_strategy_name, key_derivation_strategy_name, key, encrypted_data, encryption_artefacts, derivation_artefacts)
    encrypted_data = to_encrypted_data_value(encryption_strategy_name, encrypted_data, **encryption_artefacts)
    derived_key = to_derived_key_value(key_derivation_strategy_name, **derivation_artefacts)
    encrypted_data_with_derived_key = EncryptionValues::EncryptedDataWithDerivedKey.new(encrypted_data, derived_key)
    encrypted_data_with_derived_key.decrypt(key)
  end

  def generate_encryption_key(encryption_strategy_name = 'Aes256Gcm')
    encryption_strategy = encryption_strategy_by_name(encryption_strategy_name).new
    encryption_strategy.generate_key
  end

  def load(serialized_payload)
    encryption_strategy_name, encoded_encrypted_data, encoded_encryption_artefacts, key_derivation_strategy_name, encoded_derivation_artefacts = serialized_payload.split('.')

    encryption_strategy = encryption_strategy_by_name(encryption_strategy_name).new
    encrypted_data = Base64.urlsafe_decode64(encoded_encrypted_data)
    serialized_encryption_artefacts = YAML.safe_load(Base64.urlsafe_decode64(encoded_encryption_artefacts))
    encryption_artefacts = encryption_strategy.deserialize_artefacts(serialized_encryption_artefacts)
    payload = EncryptionValues::EncryptedData.new(encryption_strategy, encrypted_data, **encryption_artefacts)

    if key_derivation_strategy_name
      key_derivation_strategy = key_derivation_strategy_by_name(key_derivation_strategy_name).new
      serialized_derivation_artefacts = YAML.safe_load(Base64.urlsafe_decode64(encoded_derivation_artefacts))
      derivation_artefacts = key_derivation_strategy.deserialize_artefacts(serialized_derivation_artefacts)
      derived_key_value = EncryptionValues::DerivedKey.new(key_derivation_strategy, nil, **derivation_artefacts)
      payload = EncryptionValues::EncryptedDataWithDerivedKey.new(payload, derived_key_value)
    end

    payload
  end

end
