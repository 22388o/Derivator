# Derivator

Ruby implementation of EC HD key derivation ([SLIP10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md), [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)) and mnemonic sentence interpretation ([BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)).

Supports secp256k1 (Bitcoin), nist256p1 (P-256) and ed25519 (Edwards 25519) elliptic curves.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'derivator'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install derivator

## Usage

### Generate mnemonic

```bash
# bash
derivator_mnemonic
```

```ruby
# ruby
require 'derivator'

puts Derivator::Mnemonic.generate
```

### Generate seed from mnemonic

```bash
# bash
echo "finish merry file canoe cruel meadow spoil sunset pigeon depend brush step" | \
  derivator_seed_from_mnemonic

echo "spike kit woman maze culture uncle way tobacco saddle silly sunset certain" | \
  derivator_seed_from_mnemonic "my_mnemonic_password"
```

```ruby
# ruby
require 'derivator'

mnemonic = 'finish merry file canoe cruel meadow spoil sunset pigeon depend brush step'
puts Derivator::Mnemonic.seed(mnemonic)

mnemonic = 'spike kit woman maze culture uncle way tobacco saddle silly sunset certain'
puts Derivator::Mnemonic.seed(mnemonic, 'my_mnemonic_password')
```

### Generate master key and chain code from seed

```bash
# bash
echo 000102030405060708090a0b0c0d0e0f | derivator_key_from_seed ed25519
```

```ruby
# ruby
require 'derivator'

seed = '000102030405060708090a0b0c0d0e0f'
key = Derivator::Key.from_seed(seed, :ed25519)
puts "#{key.private_key_hex} #{key.chain_code_hex}"
```

### Derive child key from master key and chain code

```bash
# bash
echo 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7 90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb \
  derivator_key_from_parent "m/0'/1'/2'/2'/1000000000'" ed25519
```

```ruby
# ruby
require 'derivator'

master_private_key_hex = '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7'
master_chain_code_hex = '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb'
key = Derivator::Key.from_hex(master_private_key_hex, master_chain_code_hex, :ed25519)
derived_key = key.derive("m/0'/1'/2'/2'/1000000000'")
puts "#{derived_key.private_key_hex} #{derived_key.chain_code_hex}"
```

### Derive public key from private key

```bash
# bash
echo 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7 | \
  derivator_public_from_private ed25519
```

```ruby
# ruby
require 'derivator'

private_key_hex = '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7'
key = Derivator::Key.from_hex(private_key_hex, '', :ed25519)
puts key.public_key_hex
```

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
