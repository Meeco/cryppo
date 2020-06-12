module Cryppo
  module EncryptionValues
    class EncryptedDataWithDerivedKey

      attr_reader :encrypted_data_value, :derived_key_value
      attr_accessor :loaded_from_legacy_version

      def initialize(encrypted_data_value, derived_key_value)
        @encrypted_data_value = encrypted_data_value
        @derived_key_value = derived_key_value
      end

      def decrypt(key)
        derived_key = build_derived_key(key)
        encrypted_data_value.decrypt(derived_key)
      end

      def build_derived_key(key)
        derived_key_value.build_derived_key(key)
      end

      def serialize(version: :latest_version)
        '%s.%s' % [
          encrypted_data_value.serialize(version: version),
          derived_key_value.serialize(version: version)
        ]
      end

      ##################################
      # Some helpful accessor methods
      ##################################

      extend Forwardable

      def_delegators :@encrypted_data_value, :encryption_strategy, :encrypted_data, :encryption_artefacts
      def_delegators :@derived_key_value, :key_derivation_strategy, :derived_key, :derivation_artefacts

    end
  end
end
