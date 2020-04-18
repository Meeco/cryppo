require "bundler/setup"
require "cryppo"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

##################################
# Helper Methods
##################################

def aes_encryption_strategies
  ['Aes256Ofb', 'Aes256Gcm']
end

def all_encryption_strategies
  aes_encryption_strategies + ['Rsa4096']
end

def actively_supported_encryption_strategies
  ['Aes256Gcm', 'Rsa4096']
end
