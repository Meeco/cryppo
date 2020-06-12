RSpec.describe 'Serialization' do

  context 'upgrading serialized values' do
    it 'encryption with a generated key' do

      serialized_latest_version_format =
        "Aes256Gcm.pH_aEk0qfLoyDK2tlZUsbr3yTCylpFNbAB6fRjoIE_kJxe1n4fYqcyLj2kYM7TkUekrcPZAoj6OCPkqXGVr5KVQRo15QG9fC81Ttxdoygv3VqCQpOyARWHvfzXfaNWRW-xe1Uiau.QUAAAAACYWQABQAAAG5vbmUABWF0ABAAAAAARLWTurfYXVWxyDJ_ZdJGDAVpdgAMAAAAABDbVN0dzNq0dw_i4AA="

      serialized_legacy_format =
        "Aes256Gcm.pH_aEk0qfLoyDK2tlZUsbr3yTCylpFNbAB6fRjoIE_kJxe1n4fYqcyLj2kYM7TkUekrcPZAoj6OCPkqXGVr5KVQRo15QG9fC81Ttxdoygv3VqCQpOyARWHvfzXfaNWRW-xe1Uiau.LS0tCidhZCc6IG5vbmUKJ2F0JzogISFiaW5hcnkgfC0KICBSTFdUdXJmWVhWV3h5REovWmRKR0RBPT0KJ2l2JzogISFiaW5hcnkgfC0KICBFTnRVM1IzTTJyUjNEK0xnCg=="

      expect(Cryppo.serialization_format_upgrade_needed?(serialized_latest_version_format)).to eq(false)
      expect(Cryppo.serialization_format_upgrade_needed?(serialized_legacy_format)).to eq(true)

      upgraded = Cryppo.upgrade_serialization_format(serialized_legacy_format)
      expect(Cryppo.serialization_format_upgrade_needed?(upgraded)).to eq(false)
    end

    it 'encryption with a derived key' do

      serialized_latest_version_format =
        "Aes256Gcm.j02apR4Y0jy6BrV_sm8pP850kJGVGLLj7i_ogyRJfv-jbyHAaBmAuU3AFTDFWyalIwl2ozfv8EN64KxOoKNqFol6HirNyJzXcByQCs6qg_JttAZi21-9xvoHxKO0u3TtXwuaamcb.QUAAAAACYWQABQAAAG5vbmUABWF0ABAAAAAAFB47-aO8cExRuG7Z64fjgAVpdgAMAAAAADwhLkOj2YwXADtCIAA=.Pbkdf2Hmac.SzAAAAAQaQA-TgAABWl2ABQAAAAAfpc0yPy0psETSKUSYE8pw53TTyMQbAAgAAAAAA=="

      serialized_legacy_format =
        "Aes256Gcm.j02apR4Y0jy6BrV_sm8pP850kJGVGLLj7i_ogyRJfv-jbyHAaBmAuU3AFTDFWyalIwl2ozfv8EN64KxOoKNqFol6HirNyJzXcByQCs6qg_JttAZi21-9xvoHxKO0u3TtXwuaamcb.LS0tCidhZCc6IG5vbmUKJ2F0JzogISFiaW5hcnkgfC0KICBGQjQ3K2FPOGNFeFJ1RzdaNjRmamdBPT0KJ2l2JzogISFiaW5hcnkgfC0KICBQQ0V1UTZQWmpCY0FPMElnCg==.Pbkdf2Hmac.LS0tCidpJzogMjAwMzAKJ2l2JzogISFiaW5hcnkgfC0KICBmcGMweVB5MHBzRVRTS1VTWUU4cHc1M1RUeU09CidsJzogMzIK"

      expect(Cryppo.serialization_format_upgrade_needed?(serialized_latest_version_format)).to eq(false)
      expect(Cryppo.serialization_format_upgrade_needed?(serialized_legacy_format)).to eq(true)

      upgraded = Cryppo.upgrade_serialization_format(serialized_legacy_format)
      expect(Cryppo.serialization_format_upgrade_needed?(upgraded)).to eq(false)
    end

    it 'RSA signatures' do
      serialized =
        "Sign.Rsa4096.zJ2l2olhXzfLnzMEfD7T2rOgVOjN1kyvJobp80qvkonBloQ_qgJJYuzrphNWMzwXdHOEKgUoVE_9uwI17iNuamu0RuIllEd6QhCb4kj792hG2BqurqrkvfYwk1XczZk9fK9AkHPYw4kFU2rXtdHF973Sr2IylyaLN6J42wNKAHsrk-u_4qy8t5TOkkNCvvI3AQMppqau42dZBKvieVvpJq29C-7y-DAvwfK1sJVIAM8M9Vv1yaT8qGOYYUnzMrChJ4PG97QQOUsnBgz1vHNHMQSNV5hxu7lLG0zi-CT00987qKefPhFzHYi3x_oEqSbjFaW8xtXN_OAZe5WjL3kVJSWF6bsdpyqrrGrv52ypJeJApI6P5Mxii6998IJwjQW7mYiwiNLvb5ELA6ygBFWRDS1cs-fEEUlA65_92iU8oIAILrQqW-5q5m-y17rrCz6NPcFT137Xxx9u6X_7dt4ZNarfmIHLeEl6Ci_755aPmAzMf7emqlvuzd-A4Glr50KCOenYhkP06pdsAgTFc5nXjq6OSumibthwX5NQeRwh8E2xELraFZzqxJrsvnxZavg3vFQBZOULHt6zByg4dj6SjlJlt1zOuuAb83fILltZKzKmi_kmAJggDGq1SZKPCjRPyWhQ5ywsy7CjtzChHhETSRxVWFmc75Wi4Y3-GJZsIbU=.RnJlc2ggTm9yd2VnaWFuIHNhbG1vbiwgbGlnaHRseSBicnVzaGVkIHdpdGggb3VyIGhlcmJlZCBEaWpvbiBtdXN0YXJkIHNhdWNlLCB3aXRoIGNob2ljZSBvZiB0d28gc2lkZXMu"

      expect(Cryppo.serialization_format_upgrade_needed?(serialized)).to eq(false)
    end
  end

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

        it 'serializes the data using the legacy format' do
          key = Cryppo.generate_encryption_key(strategy_name)
          encrypted_data = Cryppo.encrypt(strategy_name, key, plain_data)
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedData)

          serialized_data = encrypted_data.serialize(version: :legacy)
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

        it 'encrypt serialize, de-serialize, decrypt using the legacy format' do
          key = Cryppo.generate_encryption_key(strategy_name)
          encrypted_data = Cryppo.encrypt(strategy_name, key, plain_data)
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedData)

          serialized_data = encrypted_data.serialize(version: :legacy)
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

        it 'serializes the data using the legacy format' do
          encrypted_data = Cryppo.encrypt_with_derived_key(
            strategy_name,
            derivation_strategy_name,
            passphrase,
            plain_data
          )
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

          serialized_data = encrypted_data.serialize(version: :legacy)
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

        it 'loads the data using the legacy version' do
          encrypted_data = Cryppo.encrypt_with_derived_key(
            strategy_name,
            derivation_strategy_name,
            passphrase,
            plain_data
          )
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

          serialized_data = encrypted_data.serialize(version: :legacy)
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

        it 'encrypt with a derived key, serialize, load, encrypt with the derived key using the legacy format' do
          encrypted_data = Cryppo.encrypt_with_derived_key(
            strategy_name,
            derivation_strategy_name,
            passphrase,
            plain_data
          )
          expect(encrypted_data).to be_a(Cryppo::EncryptionValues::EncryptedDataWithDerivedKey)

          serialized_data = encrypted_data.serialize(version: :legacy)
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
