RSpec.describe Cryppo do

  require 'json'

  it "the corpus of serialized values: encryption with generated keys" do
    f = File.new('./spec/compat.json', 'r')
    json = f.read
    f.close

    test_data = JSON.parse(json)

    test_data['encryption_with_key'].each do |one_test|
      encryption_strategy = one_test['encryption_strategy']
      expected_decryption_result = one_test['expected_decryption_result']
      _format = one_test['format']
      key = one_test['key']
      serialized = one_test['serialized']

      encrypted = Cryppo.load(serialized)

      if encryption_strategy == 'Aes256Gcm'
        key = Cryppo::EncryptionValues::EncryptionKey.new(Base64.urlsafe_decode64(key))
      end
      decrypted = encrypted.decrypt(key)
      expect(decrypted).to eq(expected_decryption_result)
    end
  end

  it "the corpus of serialized values: encryption with derived keys" do
    f = File.new('./spec/compat.json', 'r')
    json = f.read
    f.close

    test_data = JSON.parse(json)

    test_data['encryption_with_derived_key'].each do |one_test|
      _derivation_strategy = one_test['derivation_strategy']
      _encryption_strategy = one_test['encryption_strategy']
      expected_decryption_result = one_test['expected_decryption_result']
      _format = one_test['format']
      passphrase = one_test['passphrase']
      serialized = one_test['serialized']

      encrypted = Cryppo.load(serialized)
      decrypted = encrypted.decrypt(passphrase)

      expect(decrypted).to eq(expected_decryption_result)
    end
  end

  it "the corpus of serialized values: encryption with generated keys" do
    f = File.new('./spec/compat.json', 'r')
    json = f.read
    f.close

    test_data = JSON.parse(json)

    test_data['signatures'].each do |one_test|
      public_pem = one_test['public_pem']
      serialized_signature = one_test['serialized_signature']

      signature = Cryppo.load(serialized_signature)

      public_key = OpenSSL::PKey::RSA.new(public_pem)
      expect(signature.verify(public_key)).to eq(true)

      expect(signature.serialize).to eq(serialized_signature)
    end
  end
end
