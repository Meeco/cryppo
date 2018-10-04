module Cryppo
  module EncryptionStrategies

    EncryptionError = Class.new(Cryppo::Error)
    DecryptionError = Class.new(Cryppo::Error)

    class EncryptionStrategy

      include EncryptionValues::EncryptionKey::Helpers

      def strategy_name
        raise NotImplementedError, 'must implement the `strategy_name` method'
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

      def encrypt(key, data, **options)
        raise NotImplementedError, 'must implement the `encrypt` method'
      end

      def decrypt(key, encrypted_data, **options)
        raise NotImplementedError, 'must implement the `decrypt` method'
      end

      protected

      def handle_encryption_error(e)
        # wrap unhandled errors
        raise EncryptionError, e
      end

      def handle_decryption_error(e)
        # wrap unhandled errors
        raise DecryptionError, e
      end

    end
  end
end
