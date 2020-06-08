module Cryppo::Serialization
  module_function

  def load(serialized_payload)
    chunks = serialized_payload.split('.')

    if chunks.size == 5
      load_encrypted_data_with_derived_key(*chunks)

    elsif chunks.size == 3
      load_encryption_value(*chunks)

    elsif chunks.size == 4
      load_rsa_signature(*chunks)

    else
      raise InvalidSerializedValue, 'Invalid serialized value'
    end
  end

  def load_encryption_value(encryption_strategy_name, encoded_encrypted_data, encoded_encryption_artefacts)
    encryption_strategy = ::Cryppo.encryption_strategy_by_name(encryption_strategy_name).new
    encrypted_data = Base64.urlsafe_decode64(encoded_encrypted_data)
    serialized_encryption_artefacts = YAML.safe_load(Base64.urlsafe_decode64(encoded_encryption_artefacts))
    encryption_artefacts = encryption_strategy.deserialize_artefacts(serialized_encryption_artefacts)
    ::Cryppo::EncryptionValues::EncryptedData.new(encryption_strategy, encrypted_data, **encryption_artefacts)
  end

  def load_encrypted_data_with_derived_key(encryption_strategy_name, encoded_encrypted_data, encoded_encryption_artefacts, key_derivation_strategy_name, encoded_derivation_artefacts)

    payload = load_encryption_value(encryption_strategy_name, encoded_encrypted_data, encoded_encryption_artefacts)

    key_derivation_strategy = Cryppo.key_derivation_strategy_by_name(key_derivation_strategy_name).new
    serialized_derivation_artefacts = YAML.safe_load(Base64.urlsafe_decode64(encoded_derivation_artefacts))
    derivation_artefacts = key_derivation_strategy.deserialize_artefacts(serialized_derivation_artefacts)
    derived_key_value = ::Cryppo::EncryptionValues::DerivedKey.new(key_derivation_strategy, nil, **derivation_artefacts)
    ::Cryppo::EncryptionValues::EncryptedDataWithDerivedKey.new(payload, derived_key_value)
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

end
