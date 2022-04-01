lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "cryppo/version"

Gem::Specification.new do |spec|
  spec.name          = "cryppo"
  spec.version       = Cryppo::VERSION
  spec.authors       = ["Meeco"]
  spec.email         = ["info@meeco.me"]

  spec.summary       = "An encryption library"
  spec.description   = "Cryppo is a cryptographic library that enables you to encrypt and decrypt data.  Pick an encryption strategy and encrypt away!"
  spec.homepage      = ""
  spec.required_ruby_version = '>= 3.0'

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["allowed_push_host"] = "https://ruby-gems.meeco.me"
  else
    raise "RubyGems 2.0 or newer is required to protect against public gem pushes."
  end

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "openssl", "~> 3.0"
  spec.add_dependency "bson", "> 4.14"

  spec.add_development_dependency "bundler", "> 0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "> 0"
  spec.add_development_dependency "pry", "> 0.14"
  spec.add_development_dependency 'rubocop', '~> 1.26'
  spec.add_development_dependency 'rubocop-rake', '> 0'
  spec.add_development_dependency 'rubocop-rspec', '~> 2.9'
  spec.add_development_dependency 'json', '> 2.6'
end
