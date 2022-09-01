require_relative 'refinements'

module Derivator
  # {https://github.com/satoshilabs/slips/blob/master/slip-0010.md SLIP10} key derivation.
  class Key
    # secp256k1 EC private key binary prefix when DER-encoded
    SECP256K1_DER_PRIVATE_PREFIX = '303e020100301006072a8648ce3d020106052b8104000a042730250201010420'
    # nist256p1 EC private key binary prefix when DER-encoded
    NIST256P1_DER_PRIVATE_PREFIX = '3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420'
    # ed25519 EC private key binary prefix when DER-encoded
    ED25519_DER_PRIVATE_PREFIX = '302e020100300506032b657004220420'
    # ed25519 EC public key binary prefix when DER-encoded
    ED25519_DER_PUBLIC_PREFIX = '302a300506032b65700321'

    # secp256k1 BIP32/SLIP10 seed key
    SECP256K1_SEED_KEY = 'Bitcoin seed'
    # nist256p1 SLIP10 seed key
    NIST256P1_SEED_KEY = 'Nist256p1 seed'
    # ed25519 SLIP10 seed key
    ED25519_SEED_KEY = 'ed25519 seed'

    # secp256k1 largest valid private key
    SECP256K1_LARGEST_KEY = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
    # nist256p1 largest valid private key
    NIST256P1_LARGEST_KEY = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    # ed25519 largest valid private key (unlimited)
    ED25519_LARGEST_KEY = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

    # @return [Symbol] EC curve used for the key (<code>:secp256k1</code>, <code>:nist256p1</code> or <code>:ed25519</code>).
    attr_reader :curve

    # @return [String] private key (in binary format).
    attr_reader :private_key

    # @return [String] chain code (in binary format).
    attr_reader :chain_code

    using Refinements

    # Creates new key from private key and chain code hex strings.
    #
    # @param private_key_hex [String] private key hex string
    # @param chain_code_hex [String] chain code hex string
    # @param curve [Symbol] curve (<code>:secp256k1</code>, <code>:nist256p1</code> or <code>:ed25519</code>)
    # @return [Key] new key
    def self.from_hex(private_key_hex, chain_code_hex, curve = :secp256k1)
      new(private_key_hex.from_hex, chain_code_hex.from_hex, curve)
    end

    # Creates new key from seed hex string.
    #
    # @param seed_hex [String] seed hex string
    # @param curve [Symbol] curve (<code>:secp256k1</code>, <code>:nist256p1</code> or <code>:ed25519</code>)
    # @return [Key] new key
    def self.from_seed(seed_hex, curve = :secp256k1)
      seed_bytes = seed_hex.from_hex
      seed_key =
        case curve
        when :secp256k1
          SECP256K1_SEED_KEY
        when :nist256p1
          NIST256P1_SEED_KEY
        when :ed25519
          ED25519_SEED_KEY
        end

      hmac =
        OpenSSL::HMAC.hexdigest(
          "SHA512",
          seed_key,
          seed_bytes
        )

      private_key_hex = hmac[0..63]
      chain_code_hex = hmac[64..-1]
      if valid_private_key?(private_key_hex, curve)
        from_hex(private_key_hex, chain_code_hex, curve)
      else
        from_seed(hmac, curve)
      end
    end

    # Checks private key for a particular curve (used internally).
    # Primarily checks whether key value is less than order of the curve.
    #
    # @param private_key_hex [String] private key hex string
    # @param curve [Symbol] curve (<code>:secp256k1</code>, <code>:nist256p1</code> or <code>:ed25519</code>)
    # @return [true, false] whether the key is valid
    def self.valid_private_key?(private_key_hex, curve = :secp256k1)
      return false unless private_key_hex =~ /\A[a-f0-9]{64}\z/

      largest_key =
        case curve
        when :secp256k1
          SECP256K1_LARGEST_KEY
        when :nist256p1
          NIST256P1_LARGEST_KEY
        when :ed25519
          ED25519_LARGEST_KEY
        end
      private_key = private_key_hex.to_i(16)
      private_key <= largest_key && (private_key > 0 || curve == :ed25519)
    end

    # Creates private key from binary data.
    # Use {.from_hex} or {.from_seed} instead for convenience.
    #
    # @param private_key [String] private key (in binary format)
    # @param chain_code [String] chain_code (in binary format)
    # @param curve [Symbol] curve (<code>:secp256k1</code>, <code>:nist256p1</code> or <code>:ed25519</code>)
    def initialize(private_key, chain_code, curve = :secp256k1)
      @private_key = private_key.dup.freeze
      @chain_code = chain_code.dup.freeze

      unless %i[secp256k1 nist256p1 ed25519].include?(curve)
        raise ArgumentError.new('curve must be :secp256k1, :nist256p1 or :ed25519')
      end

      @curve = curve
    end

    # Compares with another {Key}.
    #
    # @param other [Key] subject of comparison
    # @return [true, false] whether {private_key}, {chain_code} and {curve} of
    #   <code>other</code> matches <code>self</code>
    def ==(other)
      return false unless %i[private_key chain_code curve].all? { |m| other.respond_to?(m) }

      private_key == other.private_key &&
        chain_code == other.chain_code &&
        curve == other.curve
    end

    # Chain code as hex string.
    #
    # @return [String]
    def chain_code_hex
      @chain_code_hex ||= @chain_code.to_hex.freeze
    end

    # {https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers BIP32 fingerprint}
    # (first 4 bytes of HASH160 of public key) as hex string.
    #
    # @return [String]
    def fingerprint
      @fingerprint ||= public_key.hash160[0..3].to_hex
    end

    # Private key as hex string.
    #
    # @return [String]
    def private_key_hex
      @private_key_hex ||= @private_key.to_hex.freeze
    end

    # Public key (in binary format).
    # Use {public_key_hex} for convenience.
    #
    # @return [String]
    def public_key
      @public_key ||= begin
        case curve
        when :ed25519
          openssl_pkey.
            public_to_der.
            to_hex.
            delete_prefix(ED25519_DER_PUBLIC_PREFIX).
            from_hex.freeze
        else
          openssl_pkey.
            public_key.
            to_octet_string(:compressed).freeze
        end
      end
    end

    # Public key as hex string.
    #
    # @return [String]
    def public_key_hex
      @public_key_hex ||= public_key.to_hex.freeze
    end

    # Derive child key.
    #
    # @param path [String] derivation path, e.g. <code>'m/0/1'</code>,
    #   <code>'5'</code>, <code>'0/3'</code>, <code>"m/0/3'/5'/1/2"</code>.
    #   Use <code>'</code> for hardened keys.
    def derive(path)
      return self if path == 'm' || path.empty?
      path = path.delete_prefix('m').delete_prefix('/')
      path = path.split('/')

      i_string = path.first
      unless i_string =~ /\A[0-9]+'?\z/
        raise ArgumentError.new("Wrong derivation segment: #{i_string.inspect}")
      end
      i = i_string.to_i
      i += 2**31 if i_string[-1] == "'"

      if curve == :ed25519 && i < 2**31
        raise ArgumentError.new("Only hardened derivation supported with ED25519, got #{i_string} instead")
      end

      if curve != :ed25519
        generator = openssl_group.generator
      end

      data =
        if i >= 2**31
          # Data for HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i))
          "00" + private_key_hex + ("%08x" % i)
        else
          # Data for HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i))
          generator.mul(private_key_hex.to_i(16)).to_octet_string(:compressed).to_hex + ("%08x" % i)
        end
      data = data.from_hex

      hmac =
        OpenSSL::HMAC.hexdigest(
          "SHA512",
          chain_code,
          data
        )
      derived_private_key_hex = hmac[0..63]
      derived_chain_code_hex = hmac[64..-1]

      if curve != :ed25519
        derived_private_key_hex, derived_chain_code_hex =
          finish_derivation(derived_private_key_hex, derived_chain_code_hex, i)
      end

      new_key = self.class.from_hex(derived_private_key_hex, derived_chain_code_hex, curve)
      new_key.derive(path[1..-1].join('/'))
    end

    # Exports key to PEM format.
    #
    # @return [String]
    def to_pem
      private_prefix =
        case curve
        when :secp256k1
          SECP256K1_DER_PRIVATE_PREFIX
        when :nist256p1
          NIST256P1_DER_PRIVATE_PREFIX
        when :ed25519
          ED25519_DER_PRIVATE_PREFIX
        end

      der = (private_prefix + private_key_hex).from_hex
      pem = <<~END
        -----BEGIN PRIVATE KEY-----
        #{der.to_base64.strip}
        -----END PRIVATE KEY-----
      END
    end

    # Creates {OpenSSL::PKey}[https://ruby-doc.org/stdlib-2.7.4/libdoc/openssl/rdoc/OpenSSL/PKey/EC/Point.html] instance.
    #
    # @return [OpenSSL::PKey::EC::Point]
    def openssl_pkey
      OpenSSL::PKey.read(to_pem)
    end

    # Creates {OpenSSL::PKey::EC::Group}[https://ruby-doc.org/stdlib-2.7.4/libdoc/openssl/rdoc/OpenSSL/PKey/EC/Group.html] instance for the key's {curve}.
    #
    # @return [OpenSSL::PKey::EC::Group]
    def openssl_group
      case curve
      when :secp256k1
        OpenSSL::PKey::EC::Group.new('secp256k1')
      when :nist256p1
        OpenSSL::PKey::EC::Group.new('prime256v1')
      end
    end

    private

    def finish_derivation(i_l_hex, i_r_hex, i)
      group = openssl_group
      i_l = i_l_hex.to_i(16)
      new_key_int = (i_l + private_key_hex.to_i(16)) % group.order
      if i_l >= group.order || new_key_int == 0
        # let I = HMAC-SHA512(Key = cpar, Data = 0x01 || IR || ser32(i) and restart at step 2.
        data = ("01" + i_r_hex + ("%08x" % i)).from_hex
        hmac =
          OpenSSL::HMAC.hexdigest(
            "SHA512",
            chain_code,
            data
          )
        finish_derivation(hmac[0..63], hmac[64..-1], i)
      else
        ["%064x" % new_key_int, i_r_hex]
      end
    end
  end
end
