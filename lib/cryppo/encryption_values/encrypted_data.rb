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

    end
  end # Encryption
end
