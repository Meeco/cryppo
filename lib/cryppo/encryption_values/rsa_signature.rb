module Cryppo
  module EncryptionValues
    MESSAGE_MAX_SIZE_BYTES = 512

    class RsaSignature
      attr_reader :signature, :data

      def initialize(signature, data)
        if data.bytes.length > MESSAGE_MAX_SIZE_BYTES
          raise ::Cryppo::SignedRsaMessageTooLong, "data too long to fit into serialization format, for data exceeding #{MESSAGE_MAX_SIZE_BYTES} bytes, consider signing hash of that data instead"
        end

        @signature = signature
        @data = data
      end

      def verify(public_key)
        unless public_key.is_a?(String) || public_key.is_a?(OpenSSL::PKey::RSA)
          raise ArgumentError.new(
            "The argument to Cryppo::EncryptionValues::RsaSignature#verify must be " \
            "a string with a PEM or an instance of OpenSSL::PKey::RSA"
          )
        end

        public_key = OpenSSL::PKey::RSA.new(public_key) if public_key.is_a?(String)

        public_key.verify(OpenSSL::Digest.new("SHA256"), @signature, @data)
      end

      def serialize
        signature_base64 = Base64.urlsafe_encode64(@signature)
        data_base64 = Base64.urlsafe_encode64(@data)
        "Sign.Rsa4096.#{signature_base64}.#{data_base64}"
      end
    end
  end
end
