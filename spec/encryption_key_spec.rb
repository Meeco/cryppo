RSpec.describe Cryppo::EncryptionValues::EncryptionKey do
  let(:wrapped_key) { Cryppo::EncryptionValues::EncryptionKey.new("my key") }
  let(:helpers) { Cryppo::EncryptionValues::EncryptionKey::Helpers }

  it "raises an error when wrapped key is implicitly coerced into a string" do
    expect { "hello" + wrapped_key }.to raise_error(Cryppo::CoercionOfEncryptedKeyToString)
  end

  it "raises an error when wrapped key is interpolated into a string" do
    expect { "hello #{wrapped_key}" }.to raise_error(Cryppo::CoercionOfEncryptedKeyToString)
  end

  it "raises an error when wrapped key is explicitly converted to a string" do
    expect { wrapped_key.to_s }.to raise_error(Cryppo::CoercionOfEncryptedKeyToString)
  end

  it "raises error when wrapped key is Marshal dumped" do
    expect { Marshal.dump(wrapped_key) }.to raise_error(Cryppo::CoercionOfEncryptedKeyToString)
  end

  it "returns the original key with unwrap_key" do
    key = "my key"

    expect(Cryppo::EncryptionValues::EncryptionKey.new(key).unwrap_key).to equal(key)
  end

  describe "Helpers" do
    it "wraps a raw key" do
      expect(helpers.wrap_encryption_key("my key").unwrap_key).to eq("my key")
    end

    it "does not wrap an already wrapped key again" do
      expect(helpers.wrap_encryption_key(wrapped_key).equal?(wrapped_key)).to eq(true)
    end

    it "unwraps a wrapped key" do
      expect(helpers.unwrap_encryption_key(wrapped_key)).to eq("my key")
    end

    it "returns a raw key unchanged when unwrapping" do
      key = "my key"

      expect(helpers.unwrap_encryption_key(key)).to equal(key)
    end
  end
end
