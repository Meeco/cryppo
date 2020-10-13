module Cryppo
  module EncryptionValues
    class RsaSignature
      attr_reader :signature, :data
      attr_accessor :loaded_from_legacy_version

      def initialize(signature, data)
        @signature = signature
        @data = data
      end

      def verify(public_key_string)
        public_key = OpenSSL::PKey::RSA.new(public_key_string)
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
