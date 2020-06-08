module Cryppo
  module EncryptionStrategies
    class Aes256Ofb < AesStrategy

      def cipher_name
        'AES-256-OFB'
      end

      Cryppo::EncryptionStrategies::EncryptionStrategy.register(self)

      def encrypt(key, data)
        cipher = new_cipher
        cipher.encrypt
        cipher.key = unwrap_encryption_key(key)
        iv = cipher.random_iv
        encrypted_data = cipher.update(data.to_s) + cipher.final
        EncryptionValues::EncryptedData.new(self, encrypted_data, iv: iv)
      rescue => e
        handle_encryption_error(e)
      end

      def decrypt(key, encrypted_data)
        decipher = new_cipher
        decipher.decrypt
        decipher.key = unwrap_encryption_key(key)
        decipher.iv = encrypted_data.encryption_artefacts[:iv]
        decipher.update(encrypted_data.encrypted_data) + decipher.final
      rescue => e
        handle_decryption_error(e)
      end

      def serialize_artefacts(artefacts)
        { 'iv' => artefacts[:iv] }
      end

      def deserialize_artefacts(payload)
        { iv: payload['iv'] }
      end

    end
  end
end
