module Cryppo::Serialization
  module_function

  # 65 is the version byte for encryption artefacts encoded with BSON
  CURRENT_VERSION_OF_ENCRYPTION_ARTEFACTS = 'A'

  # 75 is the version byte for derivation artefacts encoded with BSON
  CURRENT_VERSION_OF_DERIVATION_ARTEFACTS = 'K'

  def load(serialized_payload)
    chunks = serialized_payload.split('.')

    case chunks.size
    when 5
      load_encrypted_data_with_derived_key(*chunks)

    when 3
      load_encryption_value(*chunks)

    when 4
      load_rsa_signature(*chunks)

    else
      raise ::Cryppo::InvalidSerializedValue, 'Invalid serialized value'
    end
  end

  def load_encryption_value(encryption_strategy_name, encoded_encrypted_data, encoded_encryption_artefacts_base64)
    encryption_strategy = ::Cryppo.encryption_strategy_by_name(encryption_strategy_name).new
    encrypted_data = Base64.urlsafe_decode64(encoded_encrypted_data)

    encoded_encryption_artefacts = Base64.urlsafe_decode64(encoded_encryption_artefacts_base64)

    encryption_artefacts_hash, loaded_from_legacy_version = if encoded_encryption_artefacts[0..2] == '---'
      [load_artefacts_as_yaml(encoded_encryption_artefacts), true]
    elsif encoded_encryption_artefacts[0..0] == CURRENT_VERSION_OF_ENCRYPTION_ARTEFACTS
      [load_encryption_artefacts_as_bson(encoded_encryption_artefacts), false]
    else
      raise ::Cryppo::InvalidSerializedValue, 'unknown serialization format'
    end

    encryption_artefacts = encryption_strategy.deserialize_artefacts(encryption_artefacts_hash)
    ::Cryppo::EncryptionValues::EncryptedData.new(encryption_strategy, encrypted_data, **encryption_artefacts).tap do |res|
      res.loaded_from_legacy_version = loaded_from_legacy_version
    end
  end

  def load_encrypted_data_with_derived_key(encryption_strategy_name, encoded_encrypted_data, encoded_encryption_artefacts, key_derivation_strategy_name, encoded_derivation_artefacts)

    payload = load_encryption_value(encryption_strategy_name, encoded_encrypted_data, encoded_encryption_artefacts)

    key_derivation_strategy = Cryppo.key_derivation_strategy_by_name(key_derivation_strategy_name).new

    encoded_derivation_artefacts = Base64.urlsafe_decode64(encoded_derivation_artefacts)

    derivation_artefacts_hash, loaded_from_legacy_version = if encoded_derivation_artefacts[0..2] == '---'
      [load_artefacts_as_yaml(encoded_derivation_artefacts), true]
    elsif encoded_derivation_artefacts[0..0] == CURRENT_VERSION_OF_DERIVATION_ARTEFACTS
      [load_derivation_artefacts_as_bson(encoded_derivation_artefacts), false]
    else
      raise ::Cryppo::InvalidSerializedValue, 'unknown serialization format'
    end

    derivation_artefacts = key_derivation_strategy.deserialize_artefacts(derivation_artefacts_hash)
    derived_key_value = ::Cryppo::EncryptionValues::DerivedKey.new(key_derivation_strategy, nil, **derivation_artefacts)
    ::Cryppo::EncryptionValues::EncryptedDataWithDerivedKey.new(payload, derived_key_value).tap do |res|
      res.loaded_from_legacy_version = loaded_from_legacy_version
    end
  end

  def load_rsa_signature(signed, signing_strategy, encoded_signature, data)
    if signed == 'Sign' && signing_strategy == 'Rsa4096'
      Cryppo::EncryptionValues::RsaSignature.new(
        Base64.urlsafe_decode64(encoded_signature),
        Base64.urlsafe_decode64(data)
      )
    else
      raise UnsupportedSigningStrategy, "Serialized RSA signature expected"
    end
  end

  def load_artefacts_as_yaml(encoded_encryption_artefacts)
    YAML.safe_load(encoded_encryption_artefacts)
  end

  def load_encryption_artefacts_as_bson(encoded_encryption_artefacts)
    load_artefacts_as_bson(encoded_encryption_artefacts) do |map|
      map['at'] = map['at']&.data
      map['iv'] = map['iv']&.data
    end
  end

  def load_derivation_artefacts_as_bson(derivation_encryption_artefacts)
    load_artefacts_as_bson(derivation_encryption_artefacts) do |map|
      map['iv'] = map['iv'].data
    end
  end

  def load_artefacts_as_bson(artefacts)
    artefacts = artefacts[1..]
    buffer = BSON::ByteBuffer.new
    buffer.put_bytes(artefacts)
    map = Hash.from_bson(buffer)
    yield map
    map
  end
end
