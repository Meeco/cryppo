module Cryppo
  module EncryptionStrategies

    EncryptionError = Class.new(Cryppo::Error)
    DecryptionError = Class.new(Cryppo::Error)

    class EncryptionStrategy

      include EncryptionValues::EncryptionKey::Helpers

      def strategy_name
        self.class.name.split('::').last
      end

      def generate_key
        raise NotImplementedError, 'must implement the `generate_key` method.  Ensure the returned key is wrapped using `wrap_key`'
      end

      def encrypt_hash(key, hash)
        encrypt(key, hash.to_json)
      end

      def decrypt_hash(key, encoded_hash)
        JSON.parse(decrypt(key, encoded_hash)).symbolize_keys
      end

      def encrypt(_key, _data, **_options)
        raise NotImplementedError, 'must implement the `encrypt` method'
      end

      def decrypt(_key, _encrypted_data, **_options)
        raise NotImplementedError, 'must implement the `decrypt` method'
      end

      def serialize_artefacts(_artefacts)
        raise NotImplementedError, 'must implement the `serialize_artefacts` method.  The method should return a hash with stringified keys.'
      end

      def deserialize_artefacts(_payload)
        raise NotImplementedError, 'must implement the `deserialize_artefacts` method.  The method should return a hash with stringified keys.'
      end

      protected

      def handle_encryption_error(e)
        case e
        when Cryppo::Error
          raise e
        else
          # wrap unhandled errors
          raise EncryptionError, e
        end
      end

      def handle_decryption_error(e)
        case e
        when Cryppo::Error
          raise e
        else
          # wrap unhandled errors
          raise DecryptionError, e
        end
      end

    end
  end
end
