module Cryppo
  module EncryptionValues
    class EncryptedDataWithDerivedKey

      attr_reader :encrypted_data_value, :derived_key_value

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

      ##################################
      # Some helpful accessor methods
      ##################################

      extend Forwardable

      def_delegators :@encrypted_data_value, :encryption_strategy, :encrypted_data, :encryption_artefacts
      def_delegators :@derived_key_value, :key_derivation_strategy, :derived_key, :derivation_artefacts


    end
  end
end
