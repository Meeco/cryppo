module Cryppo
  module EncryptionStrategies
    class Aes256Gcm < AesStrategy

      IncorrectAuthTagLength = Class.new(Cryppo::Error)

      def cipher_name
        'aes-256-gcm'
      end

      def encrypt(key, data, auth_data: nil)
        cipher = new_cipher
        cipher.encrypt
        cipher.key = unwrap_encryption_key(key)
        iv = cipher.random_iv
        auth_data = auth_data.to_s
        auth_data = 'none' if auth_data.empty?
        cipher.auth_data = auth_data
        encrypted_data = cipher.update(data.to_s) + cipher.final
        auth_tag = cipher.auth_tag # produces 16 bytes tag by default
        EncryptionValues::EncryptedData.new(self, encrypted_data, iv: iv, auth_tag: auth_tag, auth_data: auth_data)
      rescue => e
        handle_encryption_error(e)
      end

      def decrypt(key, encrypted_data)
        auth_tag = encrypted_data.encryption_artefacts[:auth_tag].to_s
        raise IncorrectAuthTagLength, 'auth_tag is not 16 bytes in length' unless auth_tag.bytesize == 16

        decipher = new_cipher
        decipher.decrypt
        decipher.key = unwrap_encryption_key(key)
        decipher.iv = encrypted_data.encryption_artefacts[:iv]
        decipher.auth_tag = auth_tag
        decipher.auth_data = encrypted_data.encryption_artefacts[:auth_data]
        decipher.update(encrypted_data.encrypted_data) + decipher.final
      rescue => e
        handle_decryption_error(e)
      end

      def serialize_artefacts(artefacts)
        iv, auth_tag, auth_data = artefacts.values_at(:iv, :auth_tag, :auth_data)
        { 'iv' => iv, 'at' => auth_tag, 'ad' => auth_data }
      end

      def deserialize_artefacts(payload)
        iv, auth_tag, auth_data = payload.values_at('iv', 'at', 'ad')
        { iv: iv, auth_tag: auth_tag, auth_data: auth_data }
      end

    end
  end
end
