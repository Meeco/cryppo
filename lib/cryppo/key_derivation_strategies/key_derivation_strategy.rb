module Cryppo
  module KeyDerivationStrategies
    class KeyDerivationStrategy

      include EncryptionValues::EncryptionKey::Helpers

      def generate_derived_key(key, key_length: 32)
        raise NotImplementedError, 'must implement the `generate_derived_key` method'
      end

      def build_derived_key(key, derived_key_value)
        raise NotImplementedError, 'must implement the `build_derived_key` method.'
      end

    end
  end
end
