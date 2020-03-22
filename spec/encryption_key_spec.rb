RSpec.describe Cryppo::EncryptionValues::EncryptionKey do

  let(:wrapped_key) { Cryppo::EncryptionValues::EncryptionKey.new('my key') }

  it 'raises an error when wrapped key is implicitly coerced into a string' do
    expect { 'hello' + wrapped_key }.to raise_error(Cryppo::CoercionOfEncryptedKeyToString)
  end

  it 'raises error when wrapped key is Marshal dumped' do
    expect { Marshal.dump(wrapped_key) }.to raise_error(Cryppo::CoercionOfEncryptedKeyToString)
  end

end
