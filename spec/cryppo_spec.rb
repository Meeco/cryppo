RSpec.describe Cryppo do

  it "has a version number" do
    expect(Cryppo::VERSION).not_to be(nil)
  end

  describe 'Cryppo.generate_encryption_key' do

    all_encryption_strategies.each do |strategy_name|

      it "Key generation using strategy: #{strategy_name}" do
        encryption_key = Cryppo.generate_encryption_key(strategy_name)

        is_expected_type =
          case encryption_key
          when Cryppo::EncryptionValues::EncryptionKey
            true
          end
        expect(is_expected_type).to eq(true)
      end
    end
  end

  describe 'Encryption / decryption with a generated key' do

    let(:plain_data) { 'some plain data' }

    all_encryption_strategies.each do |strategy_name|

      it "Encryption/decryption using strategy: #{strategy_name}" do
        key = Cryppo.generate_encryption_key(strategy_name)
        encrypted_data = Cryppo.encrypt(strategy_name, key, plain_data)
        decrypted_data = encrypted_data.decrypt(key)

        expect(encrypted_data).to_not be_nil
        expect(encrypted_data).to_not eq(plain_data)

        expect(encrypted_data).to be_a_kind_of(Cryppo::EncryptionValues::EncryptedData)

        expect(decrypted_data).to eq(plain_data)
      end
    end
  end

  describe 'Encryption / decryption with a derived key' do

    let(:plain_data) { 'some plain data' }
    let(:derivation_strategy_name) { 'Pbkdf2Hmac' }
    let(:passphrase) { 'my passphrase' }

    aes_encryption_strategies.each do |strategy_name|

      it "Encryption using strategy: #{strategy_name}" do

        encrypted_data = Cryppo.encrypt_with_derived_key(strategy_name, derivation_strategy_name, passphrase, plain_data)

        expect(encrypted_data).to_not be_nil
        expect(encrypted_data).to_not eq(plain_data)
        expect(encrypted_data).to be_a_kind_of(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

        derived_key = encrypted_data.derived_key

        expect(derived_key).to_not eq(nil)
        expect(derived_key).to_not eq(passphrase)

        decrypted_data = encrypted_data.decrypt(passphrase)
        expect(decrypted_data).to eq(plain_data)
      end

    end
  end

  describe 'RSA signatures' do
    let(:data) { "Test data!" }

    it 'signing with a private key' do
      key = OpenSSL::PKey::RSA.new(4096)
      serialized_signature = Cryppo.sign_with_private_key(key.to_s, data)

      expect(serialized_signature).not_to be_nil
      expect(serialized_signature).to be_a(String)
    end

    it 'verifying with a public key' do
      key = OpenSSL::PKey::RSA.new(4096)
      serialized_signature = Cryppo.sign_with_private_key(key.to_s, data)

      signature_object = Cryppo.load_rsa_signature(serialized_signature)

      expect(signature_object.verify(key.public_key.to_s)).to eq(true)
    end
  end
end
