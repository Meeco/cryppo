RSpec.describe Cryppo do
  describe 'Serialization' do

    let(:plain_data) { 'some plain data' }
    let(:encrypted_data_value) { Cryppo.encrypt(encryption_strategy_name, key, plain_data) }
    let(:encrypted_data) { encrypted_data_value.encrypted_data }
    let(:decrypted_data) { encrypted_data_value.decrypt(key) }
    let(:serialized_data) { encrypted_data_value.serialize }
    let(:loaded_data) { Cryppo.load(serialized_data) }
    let(:decrypted_data) { loaded_data.decrypt(key) }

    context 'without a derived key' do
      all_encryption_strategies.each do |strategy_name|
        describe "Encryption using strategy: #{strategy_name}" do
          let(:encryption_strategy_name) { strategy_name }
          let(:key) { Cryppo.generate_encryption_key(encryption_strategy_name) }

          it 'serializes the data' do
            expect(serialized_data).to_not be_nil
            parts = serialized_data.split('.')
            expect(parts.length).to eq(3)
            expect(parts[0]).to eq(encryption_strategy_name)
            expect(Base64.urlsafe_decode64(parts[1])).to eq(encrypted_data)
            expect(parts[2]).to_not be_nil
          end

          it 'loads the data' do
            expect(loaded_data.encryption_strategy.strategy_name).to eq(encrypted_data_value.encryption_strategy.strategy_name)
            expect(loaded_data.encryption_artefacts).to eq(encrypted_data_value.encryption_artefacts)
          end

          it 'decrypts the data' do
            expect(decrypted_data).to eq(plain_data)
          end

        end
      end
    end

    context 'with a derived key' do
      let(:passphrase) { 'my passphrase' }
      let(:key) { passphrase }
      let(:derivation_strategy_name) { 'Pbkdf2Hmac' }
      let(:encrypted_data_value) { Cryppo.encrypt_with_derived_key(encryption_strategy_name, derivation_strategy_name, passphrase, plain_data) }
      let(:derived_key) { encrypted_data_value.derived_key }

      aes_encryption_strategies.each do |strategy_name|
        describe "Encryption using strategy: #{strategy_name}" do
          let(:encryption_strategy_name) { strategy_name }

          it 'serializes the data' do
            expect(serialized_data).to_not be_nil
            parts = serialized_data.split('.')
            expect(parts.length).to eq(5)
            expect(parts[0]).to eq(encryption_strategy_name)
            expect(Base64.urlsafe_decode64(parts[1])).to eq(encrypted_data)
            expect(parts[2]).to_not be_nil
            expect(parts[3]).to eq(derivation_strategy_name)
            expect(parts[4]).to_not be_nil
          end

          it 'loads the data' do
            expect(loaded_data.encryption_strategy.strategy_name).to eq(encrypted_data_value.encryption_strategy.strategy_name)
            expect(loaded_data.encryption_artefacts).to eq(encrypted_data_value.encryption_artefacts)
            expect(loaded_data.key_derivation_strategy.strategy_name).to eq(encrypted_data_value.key_derivation_strategy.strategy_name)
            expect(loaded_data.derivation_artefacts).to eq(encrypted_data_value.derivation_artefacts)
          end

          it 'decrypts the data' do
            expect(decrypted_data).to eq(plain_data)
          end

        end
      end
    end
  end
end
