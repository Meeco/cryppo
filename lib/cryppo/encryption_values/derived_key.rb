require 'yaml'
require 'base64'

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

      def serialise
        serialised_artefacts = key_derivation_strategy.serialise_artefacts(derivation_artefacts)
        encoded_artefacts = Base64.urlsafe_encode64(serialised_artefacts.to_yaml)
        '%s.%s' % [key_derivation_strategy.strategy_name, encoded_artefacts]
      end

    end
  end
end
