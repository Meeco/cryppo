module Cryppo
  module EncryptionValues
    class EncryptedData
      attr_reader :encryption_strategy, :encrypted_data, :encryption_artefacts

      def initialize(encryption_strategy, encrypted_data, encryption_artefacts = {})
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

        payload = serialize_artefacts(serialized_artefacts)

        encoded_artefacts = Base64.urlsafe_encode64(payload)
        "%s.%s.%s" % [encryption_strategy.strategy_name, encoded_encrypted_data, encoded_artefacts]
      end

      def serialize_artefacts(serialized_artefacts)
        ["iv", "at"].each do |k|
          value = serialized_artefacts[k]
          if value.is_a?(String)
            serialized_artefacts[k] = BSON::Binary.new(value, :generic)
          end
        end

        Cryppo::Serialization::CURRENT_VERSION_OF_ENCRYPTION_ARTEFACTS + serialized_artefacts.to_bson.to_s
      end
    end
  end
end
