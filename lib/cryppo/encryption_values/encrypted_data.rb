module Cryppo
  module EncryptionValues
    class EncryptedData

      attr_reader :encryption_strategy, :encrypted_data, :encryption_artefacts

      def initialize(encryption_strategy, encrypted_data, **encryption_artefacts)
        @encrypted_data = encrypted_data
        @encryption_strategy = encryption_strategy
        @encryption_artefacts = encryption_artefacts
      end

      def decrypt(key)
        encryption_strategy.decrypt(key, self)
      end

      def serialize
        encoded_encrypted_data = Base64.urlsafe_encode64(encrypted_data)
        serialized_artefacts = encryption_strategy.serialize_artefacts(encryption_artefacts)
        encoded_artefacts = Base64.urlsafe_encode64(serialized_artefacts.to_yaml)
        '%s.%s.%s' % [encryption_strategy.strategy_name, encoded_encrypted_data, encoded_artefacts]
      end

    end
  end
end
