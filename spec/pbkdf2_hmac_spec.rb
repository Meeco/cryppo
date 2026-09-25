RSpec.describe Cryppo::KeyDerivationStrategies::Pbkdf2Hmac do
  let(:strategy) { described_class.new }
  let(:passphrase) { "my passphrase" }

  describe "iterations" do
    it "defaults to 20000 minimum iterations with a variance of 10%" do
      expect(strategy.min_iterations).to eq(20_000)
      expect(strategy.variance).to eq(2_000)
    end

    it "computes the variance from a custom percentage" do
      expect(described_class.new(min_iterations: 1_000, iteration_variance: 50).variance).to eq(500)
    end

    it "never lets the variance drop below 1" do
      expect(described_class.new(min_iterations: 5).variance).to eq(1)
      expect(described_class.new(min_iterations: 20_000, iteration_variance: 0).variance).to eq(1)
    end

    it "uses the minimum number of iterations at the low end of the range" do
      allow(SecureRandom).to receive(:random_number).with(2_000).and_return(0)

      expect(strategy.generate_derived_key(passphrase).derivation_artefacts[:iter]).to eq(20_000)
    end

    it "stays below minimum + variance at the high end of the range" do
      allow(SecureRandom).to receive(:random_number).with(2_000).and_return(1_999)

      expect(strategy.generate_derived_key(passphrase).derivation_artefacts[:iter]).to eq(21_999)
    end

    it "stays within [min, min + variance) without stubbing" do
      strategy = described_class.new(min_iterations: 100, iteration_variance: 10)

      iterations = Array.new(50) { strategy.generate_derived_key(passphrase).derivation_artefacts[:iter] }

      expect(iterations).to all(be >= 100).and all(be < 110)
    end
  end

  describe "salt" do
    it "uses a 20 byte salt" do
      expect(strategy.generate_derived_key(passphrase).derivation_artefacts[:salt].bytesize).to eq(20)
    end

    it "uses a fresh salt for every derivation" do
      first = strategy.generate_derived_key(passphrase)
      second = strategy.generate_derived_key(passphrase)

      expect(first.derivation_artefacts[:salt]).not_to eq(second.derivation_artefacts[:salt])
      expect(first.derived_key.unwrap_key).not_to eq(second.derived_key.unwrap_key)
    end
  end

  describe "key length" do
    it "derives a 32 byte key by default" do
      derived_key_value = strategy.generate_derived_key(passphrase)

      expect(derived_key_value.derived_key.unwrap_key.bytesize).to eq(32)
      expect(derived_key_value.derivation_artefacts[:length]).to eq(32)
    end

    it "respects a custom key length when generating and rebuilding the key" do
      derived_key_value = strategy.generate_derived_key(passphrase, key_length: 16)

      expect(derived_key_value.derived_key.unwrap_key.bytesize).to eq(16)
      expect(derived_key_value.derivation_artefacts[:length]).to eq(16)
      expect(derived_key_value.build_derived_key(passphrase)).to eq(derived_key_value.derived_key.unwrap_key)
    end
  end

  describe "known answer" do
    # PBKDF2-HMAC-SHA256 test vector: P = "password", S = "salt", c = 4096, dkLen = 32
    it "derives the expected key" do
      derived_key_value = Cryppo::EncryptionValues::DerivedKey.new(strategy, nil, {salt: "salt", iter: 4096, length: 32})

      expect(derived_key_value.build_derived_key("password").unpack1("H*"))
        .to eq("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
    end

    it "rebuilds the same key that was generated" do
      derived_key_value = strategy.generate_derived_key(passphrase)

      expect(derived_key_value.build_derived_key(passphrase)).to eq(derived_key_value.derived_key.unwrap_key)
    end
  end
end
