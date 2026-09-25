RSpec.describe Cryppo do
  it "encryption_strategies" do
    expect(Cryppo.encryption_strategies.sort).to eq(
      ["Rsa4096", "Aes256Ofb", "Aes256Gcm"].sort
    )
  end

  it "derivation_strategies" do
    expect(Cryppo.derivation_strategies).to eq(["Pbkdf2Hmac"])
  end

  all_encryption_strategies.each do |strategy_name|
    it "Cryppo.generate_encryption_key with #{strategy_name}" do
      encryption_key = Cryppo.generate_encryption_key(strategy_name)

      is_expected_type =
        case encryption_key
        when Cryppo::EncryptionValues::EncryptionKey
          true
        end
      expect(is_expected_type).to eq(true)
    end
  end

  it "try to generate a key for a an invalid key generation strategy" do
    expect do
      Cryppo.generate_encryption_key("i-dont-exist")
    end.to raise_exception(Cryppo::UnsupportedEncryptionStrategy)
  end

  describe "Encryption / decryption with a generated key" do
    let(:plain_data) { "Hello world!" }

    all_encryption_strategies.each do |strategy_name|
      it "Encryption/decryption using strategy #{strategy_name}" do
        key = Cryppo.generate_encryption_key(strategy_name)
        encrypted_data = Cryppo.encrypt(strategy_name, key, plain_data)
        decrypted_data = encrypted_data.decrypt(key)

        expect(encrypted_data).not_to be_nil
        expect(encrypted_data).not_to eq(plain_data)

        expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedData)

        expect(decrypted_data).to eq(plain_data)
      end
    end

    actively_supported_encryption_strategies.each do |strategy_name|
      it "Decrypting using the wrong key of the same strategy #{strategy_name}" do
        key = Cryppo.generate_encryption_key(strategy_name)
        wrong_key = Cryppo.generate_encryption_key(strategy_name)

        encrypted_data = Cryppo.encrypt(strategy_name, key, plain_data)

        expect do
          encrypted_data.decrypt(wrong_key)
        end.to raise_exception(Cryppo::EncryptionStrategies::DecryptionError)
      end
    end

    it "trying to feed a Aes256Gcm key to a Rsa4096 decryption" do
      key = Cryppo.generate_encryption_key("Rsa4096")
      encrypted_data = Cryppo.encrypt("Rsa4096", key, plain_data)

      wrong_key = Cryppo.generate_encryption_key("Aes256Gcm")

      expect do
        encrypted_data.decrypt(wrong_key)
      end.to raise_exception(Cryppo::EncryptionStrategies::Rsa4096::UnknownKeyPairType)
    end

    it "trying to feed an Rsa4096 key to a Aes256Gcm decryption" do
      key = Cryppo.generate_encryption_key("Aes256Gcm")
      encrypted_data = Cryppo.encrypt("Aes256Gcm", key, plain_data)

      wrong_key = Cryppo.generate_encryption_key("Rsa4096")

      expect do
        encrypted_data.decrypt(wrong_key)
      end.to raise_exception(Cryppo::EncryptionStrategies::DecryptionError)
    end

    it "trying to feed a random string as a key to a Rsa4096 decryption" do
      key = Cryppo.generate_encryption_key("Rsa4096")
      encrypted_data = Cryppo.encrypt("Rsa4096", key, plain_data)

      wrong_key = "foobar"

      expect do
        encrypted_data.decrypt(wrong_key)
      end.to raise_exception(Cryppo::EncryptionStrategies::Rsa4096::UnknownKeyPairType)
    end

    it "does not leak the wrong key into the error message of a Rsa4096 decryption" do
      key = Cryppo.generate_encryption_key("Rsa4096")
      encrypted_data = Cryppo.encrypt("Rsa4096", key, plain_data)

      wrong_key = Cryppo.generate_encryption_key("Aes256Gcm")
      wrong_key_bytes = wrong_key.unwrap_key.b

      expect do
        encrypted_data.decrypt(wrong_key)
      end.to raise_exception(Cryppo::EncryptionStrategies::Rsa4096::UnknownKeyPairType) { |e|
        expect(e.message.b).not_to include(wrong_key_bytes)
        expect(e.message).to end_with("got a String")
      }
    end

    it "does not leak the wrong key into the error message of a Rsa4096 encryption" do
      expect do
        Cryppo.encrypt("Rsa4096", "not a PEM secret", plain_data)
      end.to raise_exception(Cryppo::EncryptionStrategies::Rsa4096::UnknownKeyPairType) { |e|
        expect(e.message).not_to include("not a PEM secret")
      }
    end

    it "trying to feed a random string as a key to a Aes256Gcm decryption" do
      key = Cryppo.generate_encryption_key("Aes256Gcm")
      encrypted_data = Cryppo.encrypt("Aes256Gcm", key, plain_data)

      wrong_key = "foobar"

      expect do
        encrypted_data.decrypt(wrong_key)
      end.to raise_exception(Cryppo::EncryptionStrategies::DecryptionError)
    end

    it "trying to encrypt with Aes256Gcm using a Rsa4096 key" do
      aes_key = Cryppo.generate_encryption_key("Aes256Gcm")
      expect do
        Cryppo.encrypt("Rsa4096", aes_key, plain_data)
      end.to raise_exception(Cryppo::EncryptionStrategies::Rsa4096::UnknownKeyPairType)
    end

    it "trying to encrypt with Rsa4096 using a Aes256Gcm key" do
      rsa_key = Cryppo.generate_encryption_key("Rsa4096")
      expect do
        Cryppo.encrypt("Aes256Gcm", rsa_key, plain_data)
      end.to raise_exception(Cryppo::EncryptionStrategies::EncryptionError)
    end
  end

  describe "Encryption / decryption of a hash" do
    all_encryption_strategies.each do |strategy_name|
      it "Encryption/decryption of a hash using strategy #{strategy_name}" do
        encryption_strategy = Cryppo.encryption_strategy_by_name(strategy_name).new
        key = encryption_strategy.generate_key
        hash = {"name" => "Alice", :age => 42, :address => {"city" => "Brussels"}}

        encrypted_data = encryption_strategy.encrypt_hash(key, hash)
        expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedData)

        decrypted_hash = encryption_strategy.decrypt_hash(key, encrypted_data)
        expect(decrypted_hash).to eq(name: "Alice", age: 42, address: {"city" => "Brussels"})
      end
    end
  end

  describe "Encryption / decryption with a derived key" do
    let(:plain_data) { "Hello world!" }
    let(:derivation_strategy_name) { "Pbkdf2Hmac" }
    let(:passphrase) { "my passphrase" }

    aes_encryption_strategies.each do |strategy_name|
      it "Encryption using strategy: #{strategy_name}" do
        encrypted_data = Cryppo.encrypt_with_derived_key(strategy_name, derivation_strategy_name, passphrase, plain_data)

        expect(encrypted_data).not_to be_nil
        expect(encrypted_data).not_to eq(plain_data)
        expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

        derived_key = encrypted_data.derived_key

        expect(derived_key).not_to eq(nil)
        expect(derived_key).not_to eq(passphrase)

        decrypted_data = encrypted_data.decrypt(passphrase)
        expect(decrypted_data).to eq(plain_data)
      end
    end
  end

  describe "RSA signatures" do
    let(:data) { "Test data!" }

    it "signing with a private key" do
      key = OpenSSL::PKey::RSA.new(4096)
      signature = Cryppo.sign_with_private_key(key.to_s, data)

      expect(signature).to be_a(Cryppo::EncryptionValues::RsaSignature)

      serialized_signature = signature.serialize

      expect(serialized_signature).not_to be_nil
      expect(serialized_signature).to be_a(String)
    end

    it "fail to sign too large data set" do
      msg = "a" * 513
      key = OpenSSL::PKey::RSA.new(4096)
      expect { Cryppo.sign_with_private_key(key.to_s, msg) }.to raise_error(Cryppo::SignedRsaMessageTooLong)
    end

    it "verifying with a public key" do
      key = OpenSSL::PKey::RSA.new(4096)
      signature = Cryppo.sign_with_private_key(key.to_s, data)

      expect(signature).to be_a(Cryppo::EncryptionValues::RsaSignature)

      serialized_signature = signature.serialize

      signature_object = Cryppo.load(serialized_signature)

      expect(signature_object.verify(key.public_key.to_s)).to eq(true)
    end
  end
end
