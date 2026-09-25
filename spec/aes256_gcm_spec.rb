RSpec.describe Cryppo::EncryptionStrategies::Aes256Gcm do
  let(:plain_data) { "Hello world!" }
  let(:key) { Cryppo.generate_encryption_key("Aes256Gcm") }
  let(:encrypted_data) { Cryppo.encrypt("Aes256Gcm", key, plain_data) }

  def flip_first_bit(bytes)
    bytes.dup.tap { |b| b.setbyte(0, b.getbyte(0) ^ 1) }
  end

  def decrypt_with(encrypted_data: self.encrypted_data.encrypted_data, **artefacts)
    tampered = Cryppo::EncryptionValues::EncryptedData.new(
      self.encrypted_data.encryption_strategy,
      encrypted_data,
      self.encrypted_data.encryption_artefacts.merge(artefacts)
    )
    tampered.decrypt(key)
  end

  it "decrypts the untampered data" do
    expect(decrypt_with).to eq(plain_data)
  end

  describe "tampering" do
    it "fails to decrypt a tampered ciphertext" do
      expect do
        decrypt_with(encrypted_data: flip_first_bit(encrypted_data.encrypted_data))
      end.to raise_exception(Cryppo::EncryptionStrategies::DecryptionError)
    end

    it "fails to decrypt with a tampered auth tag" do
      expect do
        decrypt_with(auth_tag: flip_first_bit(encrypted_data.encryption_artefacts[:auth_tag]))
      end.to raise_exception(Cryppo::EncryptionStrategies::DecryptionError)
    end

    it "fails to decrypt with tampered auth data" do
      expect do
        decrypt_with(auth_data: "tampered")
      end.to raise_exception(Cryppo::EncryptionStrategies::DecryptionError)
    end

    it "fails to decrypt with a tampered IV" do
      expect do
        decrypt_with(iv: flip_first_bit(encrypted_data.encryption_artefacts[:iv]))
      end.to raise_exception(Cryppo::EncryptionStrategies::DecryptionError)
    end
  end

  describe "auth tag length" do
    it "produces a 16 byte auth tag" do
      expect(encrypted_data.encryption_artefacts[:auth_tag].bytesize).to eq(16)
    end

    [nil, "", "a" * 12, "a" * 15, "a" * 17].each do |auth_tag|
      it "refuses to decrypt with an auth tag of #{auth_tag.to_s.bytesize} bytes" do
        expect do
          decrypt_with(auth_tag:)
        end.to raise_exception(Cryppo::EncryptionStrategies::Aes256Gcm::IncorrectAuthTagLength)
      end
    end
  end

  describe "auth data" do
    let(:strategy) { described_class.new }

    it "defaults the auth data to 'none'" do
      expect(encrypted_data.encryption_artefacts[:auth_data]).to eq("none")
    end

    it "keeps custom auth data through serialize, load and decrypt" do
      encrypted_data = strategy.encrypt(key, plain_data, auth_data: "some context")
      loaded = Cryppo.load(encrypted_data.serialize)

      expect(loaded.encryption_artefacts[:auth_data]).to eq("some context")
      expect(loaded.decrypt(key)).to eq(plain_data)
    end
  end

  it "uses a fresh IV for every encryption" do
    first = Cryppo.encrypt("Aes256Gcm", key, plain_data)
    second = Cryppo.encrypt("Aes256Gcm", key, plain_data)

    expect(first.encryption_artefacts[:iv]).not_to eq(second.encryption_artefacts[:iv])
    expect(first.encrypted_data).not_to eq(second.encrypted_data)
  end
end
