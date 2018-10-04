module Cryppo
  module EncryptionValues
    class DerivedKey

      include EncryptionValues::EncryptionKey::Helpers

      attr_reader :key_derivation_strategy, :derived_key, :derivation_artefacts

      def initialize(key_derivation_strategy, derived_key, **derivation_artefacts)
        @key_derivation_strategy = key_derivation_strategy
        @derived_key = wrap_encryption_key(derived_key)
        @derivation_artefacts = derivation_artefacts
      end

      def build_derived_key(key)
        key_derivation_strategy.build_derived_key(key, self)
      end

    end
  end
end
