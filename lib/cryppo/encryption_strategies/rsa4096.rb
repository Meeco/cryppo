require 'openssl'

module Cryppo
  module EncryptionStrategies
    class Rsa4096 < EncryptionStrategy

      UnknownKeyPairType = Class.new(Cryppo::Error)

      def key_length
        32 # this value has been chosen as it matches most of the AES cipher key lengths
      end

      def generate_key
        rsa_key = OpenSSL::PKey::RSA.new(4096)
        wrap_encryption_key(rsa_key)
      end

      def encrypt(rsa_key, data)
        rsa_public_key = to_rsa(rsa_key).public_key
        encrypted_data = rsa_public_key.public_encrypt(data, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        EncryptionValues::EncryptedData.new(self, encrypted_data)
      rescue UnknownKeyPairType => e
        raise e
      rescue => e
        handle_encryption_error(e)
      end

      def decrypt(rsa_key, encrypted_data)
        rsa_key = to_rsa(rsa_key)
        rsa_key.private_decrypt(encrypted_data.encrypted_data, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      rescue UnknownKeyPairType => e
        raise e
      rescue => e
        handle_decryption_error(e)
      end

      def to_rsa(rsa_key)
        rsa_key = unwrap_encryption_key(rsa_key)
        case rsa_key
        when OpenSSL::PKey::RSA
          rsa_key
        when String
          OpenSSL::PKey::RSA.new(rsa_key)
        else
          raise
        end
      rescue
        raise UnknownKeyPairType, 'Must be a PEM formatted string or an OpenSSL::PKey::RSA object: got %s' % [rsa_key]
      end

      def serialize_artefacts(_artefacts)
        {}
      end

      def deserialize_artefacts(_payload)
        {}
      end

    end
  end
end
