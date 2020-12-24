module Cryppo
  module EncryptionValues
    class RsaSignature
      attr_reader :signature, :data
      attr_accessor :loaded_from_legacy_version

      def initialize(signature, data)
        @signature = signature
        @data = data
      end

      def verify(public_key)

        unless public_key.is_a?(String) || public_key.is_a?(OpenSSL::PKey::RSA)
          raise ArgumentError.new(
            "The argument to Cryppo::EncryptionValues::RsaSignature#verify must be "\
              "a string with a PEM or an instance of OpenSSL::PKey::RSA"
          )
        end

        public_key = if public_key.is_a?(String)
          OpenSSL::PKey::RSA.new(public_key)
        else
          public_key
        end

        public_key.verify(OpenSSL::Digest.new('SHA256'), @signature, @data)
      end

      def serialize
        signature_base64 = Base64.urlsafe_encode64(@signature)
        data_base64 = Base64.urlsafe_encode64(@data)
        "Sign.Rsa4096.#{signature_base64}.#{data_base64}"
      end

    end
  end
end
