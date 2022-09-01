module Derivator
  # {https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki BIP39} mnemonic generation.
  class Mnemonic
    # Word list (ordered). Only English is supported.
    WORDS = File.readlines(__dir__ + '/word_lists/english.txt', chomp: true)

    SEED_ITERATIONS = 2048
    SEED_KEY_LENGTH = 64

    class << self
      # Generates 128 bits of random
      #
      # @return [String] 16 random bytes
      def random_bytes
        SecureRandom.random_bytes(128 / 8) # 128 bits
      end

      # Generates mnemonic.
      #
      # @param bytes [String] bytes to generate mnemonic from
      # @return [String] mnemonic (12 words)
      def generate(bytes = random_bytes)
        checksum = OpenSSL::Digest::SHA256.new(bytes).digest[0..0]
        checksum_bits = checksum[0..0].unpack('B4').first # first 4 bits
        bits = bytes.unpack('B*').first + checksum_bits
        mnemonic = bits.chars.
          each_slice(11).
          map(&:join).
          map { |x| x.to_i(2) }.
          map { |x| WORDS[x] }.
          join(' ')
      end

      # Generates master seed.
      #
      # @param mnemonic [String] mnemonic (12 words) to generate seed from
      # @param password [String] password
      def seed(mnemonic, password = '')
        salt = "mnemonic#{password}"
        result_bytes = OpenSSL::KDF.pbkdf2_hmac(
          mnemonic,
          salt: salt,
          iterations: SEED_ITERATIONS,
          length: SEED_KEY_LENGTH,
          hash: 'SHA512'
        )
        result_bytes.unpack('H*').first
      end
    end
  end
end
