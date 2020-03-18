module Cryppo
  module EncryptionValues
    class RsaSignature
      attr_reader :signature, :data

      def initialize(signature, data)
        @signature = signature
        @data = data
      end

      def verify(public_key_string)
        public_key = OpenSSL::PKey::RSA.new(public_key_string)
        public_key.verify(OpenSSL::Digest::SHA256.new, @signature, @data)
      end

      def serialize
        "Sign.Rsa4096.#{Base64.urlsafe_encode64(@signature)}.#{Base64.urlsafe_encode64(@data)}"
      end

    end
  end
end
