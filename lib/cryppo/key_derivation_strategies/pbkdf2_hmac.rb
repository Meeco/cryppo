module Cryppo
  module KeyDerivationStrategies
    class Pbkdf2Hmac < KeyDerivationStrategy
      attr_reader :min_iterations, :variance

      Cryppo::KeyDerivationStrategies::KeyDerivationStrategy.register(self)

      def initialize(min_iterations: 20_000, iteration_variance: 10)
        @min_iterations = min_iterations
        @variance = (min_iterations * (iteration_variance / 100.0)).to_i
        @variance = 1 if @variance == 0
      end

      def generate_derived_key(key, key_length: 32)
        unwrapped_key = unwrap_encryption_key(key)
        salt = OpenSSL::Random.random_bytes(20)
        iterations = min_iterations + SecureRandom.random_number(variance) # provide some randomisation to the number of iterations
        derived_key = OpenSSL::KDF.pbkdf2_hmac(unwrapped_key, salt:, iterations:, length: key_length, hash: OpenSSL::Digest.new("SHA256"))
        wrapped_derived_key = wrap_encryption_key(derived_key)
        EncryptionValues::DerivedKey.new(self, wrapped_derived_key, salt:, iter: iterations, length: key_length, hash: "SHA256")
      end

      def build_derived_key(key, derived_key_value)
        salt, iterations, key_length = derived_key_value.derivation_artefacts.values_at(:salt, :iter, :length)
        OpenSSL::KDF.pbkdf2_hmac(key, salt:, iterations:, length: key_length, hash: OpenSSL::Digest.new("SHA256"))
      end

      def serialize_artefacts(artefacts)
        salt, iterations, key_length = artefacts.values_at(:salt, :iter, :length)
        {"iv" => salt, "i" => iterations, "l" => key_length}
      end

      def deserialize_artefacts(payload)
        salt, iterations, key_length = payload.values_at("iv", "i", "l")
        {salt:, iter: iterations, length: key_length, hash: "SHA256"}
      end
    end
  end
end
