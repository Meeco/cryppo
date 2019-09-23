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
          expect(encrypted_data).to_not eq(nil)
          expect(encrypted_data).to_not eq(plain_data)
        end

        it "returns an Cryppo::EncryptionValue::EncryptedData object" do
          expect(encrypted_data_value).to be_a_kind_of(Cryppo::EncryptionValues::EncryptedData)
        end

        it "can decrypt encrypted values" do
          expect(decrypted_data).to eq(plain_data)
        end
      end # describe

    end # testing the aes strategies
  end # Cryppo.encrypt

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
          expect(encrypted_data).to_not eq(nil)
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
      end # describe

    end # testing the aes strategies
  end # Cryppo.encrypt_with_derived_key


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

  end # Cryppo.generate_encryption_key

end
