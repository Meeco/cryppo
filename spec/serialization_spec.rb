RSpec.describe "Serialization" do
  context "with a generated key" do
    let(:plain_data) { "some plain data" }

    all_encryption_strategies.each do |strategy_name|
      describe "Encryption using strategy: #{strategy_name}" do
        it "serializes the data using the latest format" do
          key = Cryppo.generate_encryption_key(strategy_name)
          encrypted_data = Cryppo.encrypt(strategy_name, key, plain_data)
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedData)

          serialized_data = encrypted_data.serialize
          expect(serialized_data).to be_a(String)

          parts = serialized_data.split(".")
          expect(parts.length).to eq(3)
          expect(parts[0]).to eq(strategy_name)
          expect(Base64.urlsafe_decode64(parts[1])).to eq(encrypted_data.encrypted_data)
          expect(parts[2]).not_to be_nil
        end

        it "encrypt serialize, de-serialize, decrypt using the latest format" do
          key = Cryppo.generate_encryption_key(strategy_name)
          encrypted_data = Cryppo.encrypt(strategy_name, key, plain_data)
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedData)

          serialized_data = encrypted_data.serialize
          expect(serialized_data).to be_a(String)

          loaded_encrypted_data = Cryppo.load(serialized_data)
          expect(loaded_encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedData)

          expect(loaded_encrypted_data.encryption_strategy.strategy_name).to eq(encrypted_data.encryption_strategy.strategy_name)
          expect(loaded_encrypted_data.encryption_artefacts).to eq(encrypted_data.encryption_artefacts)

          decrypted_data = loaded_encrypted_data.decrypt(key)
          expect(decrypted_data).to be_a(String)

          expect(decrypted_data).to eq(plain_data)
        end
      end
    end

    it "fail to load a message if it is encoded with basic base64 variant (not url safe)" do
      cryppo_messages_with_plain_base64_encoding = [
        "Aes256Gcm.MKqNIBDJd0GiSuKRtJVW.QUAAAAAFaXYADAAAAACFQp/FfChOjJ+C0lgFYXQAEAAAAABGeM6DOVX61jAE",
        "Sign.Rsa4096.MKqNIBDJd0GiSuKRtJVW.QUAAAAAFaXYADAAAAACFQp/FfChOjJ+C0lgFYXQAEAAAAABGeM6DOVX61jAE",
        "Aes256Gcm.MKqNIBDJd0GiSuKRtJVW.QUAAAAAFaXYADAAAAACFQp/FfChOjJ+C0lgFYXQAEAAAAABGeM6DOVX61jAE.Pbkdf2Hmac.SzAAAAAQaQA-TgAABWl2ABQAAAAAfpc0yPy0psETSKUSYE8pw53TTyMQbAAgAAAAAA=="
      ]
      cryppo_messages_with_plain_base64_encoding.each do |msg|
        expect { Cryppo.load(msg) }.to raise_error(Cryppo::UnsupportedBase64Encoding)
      end
    end
  end

  context "with a signature" do
    it "fail to load a signature with an unsupported prefix or signing strategy" do
      invalid_signatures = [
        "Foo.Rsa4096.YWJj.YWJj",
        "Sign.Rsa2048.YWJj.YWJj"
      ]
      invalid_signatures.each do |msg|
        expect { Cryppo.load(msg) }.to raise_error(Cryppo::UnsupportedSigningStrategy, "Serialized RSA signature expected")
      end
    end
  end

  context "with a derived key" do
    let(:passphrase) { "my passphrase" }
    let(:derivation_strategy_name) { "Pbkdf2Hmac" }
    let(:plain_data) { "some plain data" }

    aes_encryption_strategies.each do |strategy_name|
      describe "Encryption using strategy: #{strategy_name}" do
        it "serializes the data using the latest format" do
          encrypted_data = Cryppo.encrypt_with_derived_key(
            strategy_name,
            derivation_strategy_name,
            passphrase,
            plain_data
          )
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

          serialized_data = encrypted_data.serialize
          expect(serialized_data).to be_a(String)

          parts = serialized_data.split(".")
          expect(parts.length).to eq(5)
          expect(parts[0]).to eq(strategy_name)
          expect(Base64.urlsafe_decode64(parts[1])).to eq(encrypted_data.encrypted_data)
          expect(parts[2]).not_to be_nil
          expect(parts[3]).to eq(derivation_strategy_name)
          expect(parts[4]).not_to be_nil
        end

        it "loads the data using the latest version" do
          encrypted_data = Cryppo.encrypt_with_derived_key(
            strategy_name,
            derivation_strategy_name,
            passphrase,
            plain_data
          )
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

          serialized_data = encrypted_data.serialize
          expect(serialized_data).to be_a(String)

          loaded_encrypted_data = Cryppo.load(serialized_data)
          expect(loaded_encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

          expect(loaded_encrypted_data.encryption_strategy.strategy_name).to eq(encrypted_data.encryption_strategy.strategy_name)
          expect(loaded_encrypted_data.encryption_artefacts).to eq(encrypted_data.encryption_artefacts)
          expect(loaded_encrypted_data.key_derivation_strategy.strategy_name).to eq(encrypted_data.key_derivation_strategy.strategy_name)
          expect(loaded_encrypted_data.derivation_artefacts).to eq(encrypted_data.derivation_artefacts)
        end

        it "encrypt with a derived key, serialize, load, encrypt with the derived key using the latest format" do
          encrypted_data = Cryppo.encrypt_with_derived_key(
            strategy_name,
            derivation_strategy_name,
            passphrase,
            plain_data
          )
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

          serialized_data = encrypted_data.serialize
          expect(serialized_data).to be_a(String)

          loaded_encrypted_data = Cryppo.load(serialized_data)
          expect(loaded_encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

          decrypted_data = loaded_encrypted_data.decrypt(passphrase)
          expect(decrypted_data).to be_a(String)

          expect(decrypted_data).to eq(plain_data)
        end
      end
    end
  end

  context "with invalid serialized values" do
    def encode(bytes)
      Base64.urlsafe_encode64(bytes)
    end

    let(:serialized_with_derived_key) do
      Cryppo.encrypt_with_derived_key("Aes256Gcm", "Pbkdf2Hmac", "my passphrase", "some plain data").serialize.split(".")
    end

    ["", "Aes256Gcm", "Aes256Gcm.YWJj", "Aes256Gcm.YWJj.YWJj.Pbkdf2Hmac.YWJj.YWJj"].each do |serialized|
      it "fails to load a value with #{serialized.split(".").size} chunks" do
        expect { Cryppo.load(serialized) }.to raise_error(Cryppo::InvalidSerializedValue, "Invalid serialized value")
      end
    end

    it "fails to load a value with an unknown encryption strategy" do
      expect do
        Cryppo.load("Nope.YWJj.#{encode("A" + {}.to_bson.to_s)}")
      end.to raise_error(Cryppo::UnsupportedEncryptionStrategy)
    end

    it "fails to load a value with an unknown key derivation strategy" do
      serialized_with_derived_key[3] = "Nope"

      expect do
        Cryppo.load(serialized_with_derived_key.join("."))
      end.to raise_error(Cryppo::UnsupportedKeyDerivationStrategy)
    end

    it "fails to load encryption artefacts with an unknown version byte" do
      expect do
        Cryppo.load("Aes256Gcm.YWJj.#{encode("Z" + {}.to_bson.to_s)}")
      end.to raise_error(Cryppo::InvalidSerializedValue, "unknown serialization format")
    end

    it "fails to load encryption artefacts in the legacy YAML format" do
      expect do
        Cryppo.load("Aes256Gcm.YWJj.#{encode("---\niv: x\n")}")
      end.to raise_error(Cryppo::InvalidSerializedValue, /support for yaml based format has been dropped/)
    end

    it "fails to load derivation artefacts with an unknown version byte" do
      serialized_with_derived_key[4] = encode("Z" + {}.to_bson.to_s)

      expect do
        Cryppo.load(serialized_with_derived_key.join("."))
      end.to raise_error(Cryppo::InvalidSerializedValue, "unknown serialization format")
    end

    it "fails to load derivation artefacts in the legacy YAML format" do
      serialized_with_derived_key[4] = encode("---\niv: x\n")

      expect do
        Cryppo.load(serialized_with_derived_key.join("."))
      end.to raise_error(Cryppo::InvalidSerializedValue, /support for yaml based format has been dropped/)
    end
  end

  context "when serializing a loaded value again" do
    all_encryption_strategies.each do |strategy_name|
      it "produces the same string using strategy #{strategy_name}" do
        key = Cryppo.generate_encryption_key(strategy_name)
        serialized = Cryppo.encrypt(strategy_name, key, "some plain data").serialize

        expect(Cryppo.load(serialized).serialize).to eq(serialized)
      end
    end

    aes_encryption_strategies.each do |strategy_name|
      it "produces the same string with a derived key using strategy #{strategy_name}" do
        serialized = Cryppo.encrypt_with_derived_key(strategy_name, "Pbkdf2Hmac", "my passphrase", "some plain data").serialize

        expect(Cryppo.load(serialized).serialize).to eq(serialized)
      end
    end

    it "produces the same string for a signature" do
      private_key = OpenSSL::PKey::RSA.new(4096)
      serialized = Cryppo.sign_with_private_key(private_key.to_pem, "Test data!").serialize

      expect(Cryppo.load(serialized).serialize).to eq(serialized)
    end
  end
end
