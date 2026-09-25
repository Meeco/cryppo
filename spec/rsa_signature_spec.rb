RSpec.describe Cryppo::EncryptionValues::RsaSignature do
  let(:data) { "Test data!" }

  describe "verification" do
    let(:private_key) { OpenSSL::PKey::RSA.new(4096) }
    let(:signature) { Cryppo.sign_with_private_key(private_key.to_pem, data) }

    def flip_first_bit(bytes)
      bytes.dup.tap { |b| b.setbyte(0, b.getbyte(0) ^ 1) }
    end

    it "verifies with the matching public key" do
      expect(signature.verify(private_key.public_key)).to eq(true)
    end

    it "does not verify with another public key" do
      other_public_key = OpenSSL::PKey::RSA.new(4096).public_key

      expect(signature.verify(other_public_key)).to eq(false)
      expect(signature.verify(other_public_key.to_pem)).to eq(false)
      expect(Cryppo.verify(signature, other_public_key)).to eq(false)
    end

    it "does not verify tampered data" do
      tampered = described_class.new(signature.signature, "Test data?")

      expect(tampered.verify(private_key.public_key)).to eq(false)
    end

    it "does not verify a tampered signature" do
      tampered = described_class.new(flip_first_bit(signature.signature), data)

      expect(tampered.verify(private_key.public_key)).to eq(false)
    end

    it "does not verify tampered data after a serialize/load round-trip" do
      _sign, _strategy, encoded_signature, _encoded_data = signature.serialize.split(".")
      tampered = Cryppo.load("Sign.Rsa4096.#{encoded_signature}.#{Base64.urlsafe_encode64("Test data?")}")

      expect(tampered.verify(private_key.public_key)).to eq(false)
    end
  end

  describe "argument guards" do
    let(:signature) { described_class.new("signature", data) }

    it "Cryppo.verify requires an RsaSignature as the first argument" do
      expect do
        Cryppo.verify(signature.serialize, "public key")
      end.to raise_exception(ArgumentError, /first argument to Cryppo.verify/)
    end

    it "Cryppo.verify requires a PEM string or an OpenSSL::PKey::RSA as the second argument" do
      expect do
        Cryppo.verify(signature, nil)
      end.to raise_exception(ArgumentError, /second argument to Cryppo.verify/)
    end

    it "RsaSignature#verify requires a PEM string or an OpenSSL::PKey::RSA" do
      expect do
        signature.verify(nil)
      end.to raise_exception(ArgumentError, /RsaSignature#verify/)
    end
  end

  describe "data size limit" do
    it "accepts data of exactly 512 bytes" do
      expect { described_class.new("signature", "a" * 512) }.not_to raise_exception
    end

    it "rejects data over 512 bytes" do
      expect do
        described_class.new("signature", "a" * 513)
      end.to raise_exception(Cryppo::SignedRsaMessageTooLong)
    end

    it "counts bytes, not characters" do
      expect { described_class.new("signature", "é" * 256) }.not_to raise_exception

      expect do
        described_class.new("signature", "é" * 257)
      end.to raise_exception(Cryppo::SignedRsaMessageTooLong)
    end
  end
end
