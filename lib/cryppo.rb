require 'yaml'
require 'base64'
require 'openssl'
require 'securerandom'
require 'bson'

module Cryppo
  module_function

  Error = Class.new(StandardError)
  UnsupportedEncryptionStrategy = Class.new(Error)
  UnsupportedKeyDerivationStrategy = Class.new(Error)
  CoercionOfEncryptedKeyToString = Class.new(Error)
  UnsupportedSigningStrategy = Class.new(Error)
  InvalidSerializedValue = Class.new(Error)

  autoload :Serialization, 'cryppo/serialization'

  module EncryptionStrategies
    autoload :EncryptionStrategy, 'cryppo/encryption_strategies/encryption_strategy'
    autoload :AesStrategy, 'cryppo/encryption_strategies/aes_strategy'
    autoload :Aes256Ofb, 'cryppo/encryption_strategies/aes256_ofb'
    autoload :Aes256Gcm, 'cryppo/encryption_strategies/aes256_gcm'
    autoload :Rsa4096, 'cryppo/encryption_strategies/rsa4096'

    def self.by_name(strategy_name)
      const_get(strategy_name).tap do |klass|
        unless klass < Cryppo::EncryptionStrategies::EncryptionStrategy
          raise UnsupportedEncryptionStrategy.new("#{klass} is not a Cryppo::EncryptionStrategies::EncryptionStrategy")
        end
      end
    rescue NameError => e
      raise UnsupportedEncryptionStrategy, e.message
    end
  end

  module EncryptionValues
    autoload :DerivedKey, 'cryppo/encryption_values/derived_key'
    autoload :EncryptedDataWithDerivedKey, 'cryppo/encryption_values/encrypted_data_with_derived_key'
    autoload :EncryptedData, 'cryppo/encryption_values/encrypted_data'
    autoload :EncryptionKey, 'cryppo/encryption_values/encryption_key'
    autoload :RsaSignature, 'cryppo/encryption_values/rsa_signature'
  end

  module KeyDerivationStrategies
    autoload :KeyDerivationStrategy, 'cryppo/key_derivation_strategies/key_derivation_strategy'
    autoload :Pbkdf2Hmac, 'cryppo/key_derivation_strategies/pbkdf2_hmac'

    def self.by_name(strategy_name)
      const_get(strategy_name).tap do |klass|
        unless klass < Cryppo::KeyDerivationStrategies::KeyDerivationStrategy
          raise UnsupportedKeyDerivationStrategy.new("#{klass} is not a Cryppo::KeyDerivationStrategies::KeyDerivationStrategy")
        end
      end
    rescue NameError => e
      raise UnsupportedKeyDerivationStrategy, e.message
    end
  end

  def encryption_strategies
    Cryppo::EncryptionStrategies::Aes256Gcm
    Cryppo::EncryptionStrategies::Aes256Ofb
    Cryppo::EncryptionStrategies::Rsa4096
    Cryppo::EncryptionStrategies::EncryptionStrategy.strategies
  end

  def derivation_strategies
    Cryppo::KeyDerivationStrategies::Pbkdf2Hmac
    Cryppo::KeyDerivationStrategies::KeyDerivationStrategy.strategies
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

  def to_encrypted_data_value(encryption_strategy_name, encrypted_data, encryption_artefacts)
    encryption_strategy = encryption_strategy_by_name(encryption_strategy_name).new
    EncryptionValues::EncryptedData.new(encryption_strategy, encrypted_data, encryption_artefacts)
  end

  def to_derived_key_value(key_derivation_strategy_name, derivation_artefacts)
    key_derivation_strategy = key_derivation_strategy_by_name(key_derivation_strategy_name).new
    EncryptionValues::DerivedKey.new(key_derivation_strategy, nil, derivation_artefacts)
  end

  def decrypt(encryption_strategy_name, key, encrypted_data, encryption_artefacts = {})
    encrypted_data = to_encrypted_data_value(encryption_strategy_name, encrypted_data, encryption_artefacts)
    encrypted_data.decrypt(key)
  end

  def decrypt_with_derived_key(encryption_strategy_name, key_derivation_strategy_name, key, encrypted_data, encryption_artefacts, derivation_artefacts)
    encrypted_data = to_encrypted_data_value(encryption_strategy_name, encrypted_data, encryption_artefacts)
    derived_key = to_derived_key_value(key_derivation_strategy_name, derivation_artefacts)
    encrypted_data_with_derived_key = EncryptionValues::EncryptedDataWithDerivedKey.new(encrypted_data, derived_key)
    encrypted_data_with_derived_key.decrypt(key)
  end

  def generate_encryption_key(encryption_strategy_name = 'Aes256Gcm')
    encryption_strategy = encryption_strategy_by_name(encryption_strategy_name).new
    encryption_strategy.generate_key
  end

  def load(serialized_payload)
    Cryppo::Serialization.load(serialized_payload)
  end

  def serialization_format_upgrade_needed?(serialized_payload)
    !!Cryppo::Serialization.load(serialized_payload).loaded_from_legacy_version
  end

  def upgrade_serialization_format(serialized_payload)
    Cryppo::Serialization.load(serialized_payload).serialize
  end

  def sign_with_private_key(private_key_string, data)
    digest = OpenSSL::Digest.new('SHA256')
    private_key = OpenSSL::PKey::RSA.new(private_key_string)
    signature = private_key.sign(digest, data)
    EncryptionValues::RsaSignature.new(signature, data)
  end

end
