Gem::Specification.new do |spec|
  spec.name          = 'derivator'
  spec.version       = '0.1'
  spec.authors       = ['WAGMI LTD.']
  spec.email         = ['debifi@debifi.com']

  spec.summary       = 'BIP-0039, BIP-0032, SLIP-0010 elliptic curve (P-256, ED25519, SECP256K1) keys derivator'
  spec.homepage      = 'https://gitlab.com/debifi-public/derivator'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 2.4.0'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{\A(?:test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'yard'

  spec.add_dependency 'openssl', '>= 3.0'
end
