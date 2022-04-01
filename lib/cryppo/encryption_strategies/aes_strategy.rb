module Cryppo
  module EncryptionStrategies
    class AesStrategy < EncryptionStrategy
      def cipher_name
        raise NotImplementedError, "must implement the `cipher_name` method"
      end

      def new_cipher
        OpenSSL::Cipher.new(cipher_name)
      end

      def key_length
        new_cipher.key_len
      end

      def generate_key
        key = new_cipher.random_key
        wrap_encryption_key(key)
      end
    end
  end
end
