module Cryppo
  module EncryptionValues
    class DerivedKey

      include EncryptionValues::EncryptionKey::Helpers

      attr_reader :key_derivation_strategy, :derived_key, :derivation_artefacts

      def initialize(key_derivation_strategy, derived_key, derivation_artefacts)
        @key_derivation_strategy = key_derivation_strategy
        @derived_key = wrap_encryption_key(derived_key)
        @derivation_artefacts = derivation_artefacts
      end

      def build_derived_key(key)
        key_derivation_strategy.build_derived_key(key, self)
      end

      def serialize
        serialized_artefacts = key_derivation_strategy.serialize_artefacts(derivation_artefacts)

        payload = serialize_artefacts(serialized_artefacts)

        encoded_artefacts = Base64.urlsafe_encode64(payload)
        '%s.%s' % [key_derivation_strategy.strategy_name, encoded_artefacts]
      end

      def serialize_artefacts(serialized_artefacts)
        serialized_artefacts['iv'] = BSON::Binary.new(serialized_artefacts['iv'], :generic)
        Cryppo::Serialization::CURRENT_VERSION_OF_DERIVATION_ARTEFACTS + serialized_artefacts.to_bson.to_s
      end

    end
  end
end
