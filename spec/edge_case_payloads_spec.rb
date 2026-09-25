RSpec.describe "Edge-case payloads" do
  describe "AES strategies" do
    payloads = {
      "an empty string" => "",
      "binary data" => (0..255).map(&:chr).join.b,
      "a large payload" => SecureRandom.random_bytes(1024 * 1024)
    }

    aes_encryption_strategies.each do |strategy_name|
      payloads.each do |description, payload|
        it "encrypts, serializes, loads and decrypts #{description} using strategy #{strategy_name}" do
          key = Cryppo.generate_encryption_key(strategy_name)
          encrypted_data = Cryppo.encrypt(strategy_name, key, payload)

          decrypted_data = Cryppo.load(encrypted_data.serialize).decrypt(key)

          expect(decrypted_data).to eq(payload)
        end
      end

      it "returns the decrypted UTF-8 input as a binary string using strategy #{strategy_name}" do
        key = Cryppo.generate_encryption_key(strategy_name)
        plain_data = "héllo wörld ✓"

        decrypted_data = Cryppo.encrypt(strategy_name, key, plain_data).decrypt(key)

        expect(decrypted_data.encoding).to eq(Encoding::BINARY)
        expect(decrypted_data).not_to eq(plain_data)
        expect(decrypted_data.bytes).to eq(plain_data.bytes)
        expect(decrypted_data.force_encoding("UTF-8")).to eq(plain_data)
      end
    end
  end

  describe "Rsa4096" do
    let(:private_key) { OpenSSL::PKey::RSA.new(4096) }
    let(:key) { Cryppo::EncryptionValues::EncryptionKey.new(private_key) }

    it "encrypts and decrypts an empty string" do
      expect(Cryppo.encrypt("Rsa4096", key, "").decrypt(key)).to eq("")
    end

    it "encrypts and decrypts binary data" do
      payload = (0..255).map(&:chr).join.b

      expect(Cryppo.encrypt("Rsa4096", key, payload).decrypt(key)).to eq(payload)
    end

    it "encrypts and decrypts a payload of the maximum size for OAEP padding (470 bytes)" do
      payload = "a" * 470

      expect(Cryppo.encrypt("Rsa4096", key, payload).decrypt(key)).to eq(payload)
    end

    it "fails to encrypt a payload over the maximum size for OAEP padding" do
      expect do
        Cryppo.encrypt("Rsa4096", key, "a" * 471)
      end.to raise_exception(Cryppo::EncryptionStrategies::EncryptionError)
    end

    {
      "an OpenSSL::PKey::RSA public key" => -> { private_key.public_key },
      "a public key PEM" => -> { private_key.public_key.to_pem },
      "a private key PEM" => -> { private_key.to_pem }
    }.each do |description, encryption_key|
      it "encrypts with #{description}" do
        encrypted_data = Cryppo.encrypt("Rsa4096", instance_exec(&encryption_key), "Hello world!")

        expect(encrypted_data.decrypt(key)).to eq("Hello world!")
      end
    end

    {
      "an OpenSSL::PKey::RSA public key" => -> { private_key.public_key },
      "a public key PEM" => -> { private_key.public_key.to_pem }
    }.each do |description, decryption_key|
      it "fails to decrypt with #{description}" do
        encrypted_data = Cryppo.encrypt("Rsa4096", key, "Hello world!")

        expect do
          encrypted_data.decrypt(instance_exec(&decryption_key))
        end.to raise_exception(Cryppo::EncryptionStrategies::DecryptionError)
      end
    end
  end
end
