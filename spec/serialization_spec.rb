RSpec.describe 'Serialization' do

  context 'with a generated key' do

    let(:plain_data) { 'some plain data' }

    all_encryption_strategies.each do |strategy_name|
      describe "Encryption using strategy: #{strategy_name}" do

        it 'serializes the data using the latest format' do
          key = Cryppo.generate_encryption_key(strategy_name)
          encrypted_data = Cryppo.encrypt(strategy_name, key, plain_data)
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedData)

          serialized_data = encrypted_data.serialize
          expect(serialized_data).to be_a(String)

          parts = serialized_data.split('.')
          expect(parts.length).to eq(3)
          expect(parts[0]).to eq(strategy_name)
          expect(Base64.urlsafe_decode64(parts[1])).to eq(encrypted_data.encrypted_data)
          expect(parts[2]).to_not be_nil
        end

        it 'encrypt serialize, de-serialize, decrypt using the latest format' do
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

    it 'fail to load a message if it is encoded with basic base64 variant (not url safe)' do
      cryppo_messages_with_plain_base64_encoding = [
        'Aes256Gcm.MKqNIBDJd0GiSuKRtJVW.QUAAAAAFaXYADAAAAACFQp/FfChOjJ+C0lgFYXQAEAAAAABGeM6DOVX61jAE',
        'Sign.Rsa4096.MKqNIBDJd0GiSuKRtJVW.QUAAAAAFaXYADAAAAACFQp/FfChOjJ+C0lgFYXQAEAAAAABGeM6DOVX61jAE',
        'Aes256Gcm.MKqNIBDJd0GiSuKRtJVW.QUAAAAAFaXYADAAAAACFQp/FfChOjJ+C0lgFYXQAEAAAAABGeM6DOVX61jAE.Pbkdf2Hmac.SzAAAAAQaQA-TgAABWl2ABQAAAAAfpc0yPy0psETSKUSYE8pw53TTyMQbAAgAAAAAA=='
      ]
      cryppo_messages_with_plain_base64_encoding.each do |msg|
        expect { Cryppo.load(msg) }.to raise_error(::Cryppo::UnsupportedBase64Encoding)
      end
    end
  end

  context 'with a derived key' do

    let(:passphrase) { 'my passphrase' }
    let(:derivation_strategy_name) { 'Pbkdf2Hmac' }
    let(:plain_data) { 'some plain data' }

    aes_encryption_strategies.each do |strategy_name|
      describe "Encryption using strategy: #{strategy_name}" do

        it 'serializes the data using the latest format' do
          encrypted_data = Cryppo.encrypt_with_derived_key(
            strategy_name,
            derivation_strategy_name,
            passphrase,
            plain_data
          )
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

          serialized_data = encrypted_data.serialize
          expect(serialized_data).to be_a(String)

          parts = serialized_data.split('.')
          expect(parts.length).to eq(5)
          expect(parts[0]).to eq(strategy_name)
          expect(Base64.urlsafe_decode64(parts[1])).to eq(encrypted_data.encrypted_data)
          expect(parts[2]).to_not be_nil
          expect(parts[3]).to eq(derivation_strategy_name)
          expect(parts[4]).to_not be_nil
        end

        it 'loads the data using the latest version' do
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

        it 'encrypt with a derived key, serialize, load, encrypt with the derived key using the latest format' do
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
end
