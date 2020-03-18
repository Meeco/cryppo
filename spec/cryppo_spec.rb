RSpec.describe Cryppo do

  it "has a version number" do
    expect(Cryppo::VERSION).not_to be nil
  end

  let(:plain_data) { 'some plain data' }
  let(:encrypted_data_value) { Cryppo.encrypt(encryption_strategy_name, key, plain_data) }
  let(:encrypted_data) { encrypted_data_value.encrypted_data }
  let(:decrypted_data) { encrypted_data_value.decrypt(key) }

  describe 'Cryppo.encrypt' do
    all_encryption_strategies.each do |strategy_name|

      describe "Encryption using strategy: #{strategy_name}" do
        let(:encryption_strategy_name) { strategy_name }
        let(:key) { Cryppo.generate_encryption_key(encryption_strategy_name) }

        it "encrypts data" do
          expect(encrypted_data).to_not be_nil
          expect(encrypted_data).to_not eq(plain_data)
        end

        it "returns an Cryppo::EncryptionValue::EncryptedData object" do
          expect(encrypted_data_value).to be_a_kind_of(Cryppo::EncryptionValues::EncryptedData)
        end

        it "can decrypt encrypted values" do
          expect(decrypted_data).to eq(plain_data)
        end
      end

    end
  end

  describe 'Cryppo.encrypt_with_derived_key' do
    let(:passphrase) { 'my passphrase' }
    let(:key) { passphrase }
    let(:derivation_strategy_name) { 'Pbkdf2Hmac' }
    let(:encrypted_data_value) { Cryppo.encrypt_with_derived_key(encryption_strategy_name, derivation_strategy_name, passphrase, plain_data) }
    let(:derived_key) { encrypted_data_value.derived_key }

    aes_encryption_strategies.each do |strategy_name|

      describe "Encryption using strategy: #{strategy_name}" do
        let(:encryption_strategy_name) { strategy_name }

        it "encrypts data" do
          expect(encrypted_data).to_not be_nil
          expect(encrypted_data).to_not eq(plain_data)
        end

        it "returns an Cryppo::EncryptionValue::EncryptedData object" do
          expect(encrypted_data_value).to be_a_kind_of(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)
        end

        it "has a derived key" do
          expect(derived_key).to_not eq(nil)
          expect(derived_key).to_not eq(passphrase)
        end

        it "can decrypt encrypted values" do
          expect(decrypted_data).to eq(plain_data)
        end
      end

    end
  end

  describe 'Cryppo.generate_encryption_key' do

    aes_encryption_strategies.each do |strategy_name|
      describe "Key generation using strategy: #{strategy_name}" do

        let(:encryption_key) { Cryppo.generate_encryption_key(strategy_name) }

        it 'returns a key wrapped in Cryppo::EncryptionValues::EncryptedKey' do
          is_expected_type =
            case encryption_key
            when Cryppo::EncryptionValues::EncryptionKey
              true
            end
          expect(is_expected_type).to eq(true)
        end
      end
    end

  end

  let!(:pkey) { OpenSSL::PKey::RSA.new(4096) }
  let!(:data) { "Test data!" }

  describe 'Cryppo.sign_with_private_key' do
    let(:serialized_signature) { Cryppo.sign_with_private_key(pkey.to_s, data) }

    it 'serialized_signature is present' do
      expect(serialized_signature).not_to(be_nil)
    end
  end

  describe 'Cryppo.load_rsa_signature' do
    let(:serialized_signature) { Cryppo.sign_with_private_key(pkey.to_s, data) }
    let(:signature_object) { Cryppo.load_rsa_signature(serialized_signature) }

    it 'verification succeeds' do
      expect(signature_object.verify(pkey.public_key.to_s)).to eq(true)
    end
  end

end
