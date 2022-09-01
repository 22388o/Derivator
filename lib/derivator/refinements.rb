module Derivator
  # Internally used refinements
  module Refinements
    refine String do
      def to_hex
        unpack('H*').first
      end

      def from_hex
        [self].pack('H*')
      end

      def to_base64
        Base64.encode64(self)
      end

      def from_base64
        Base64.decode64(self)
      end

      def parse_der
        OpenSSL::ASN1.decode(self)
      end

      def to_der_octet_string
        OpenSSL::ASN1::OctetString.new(self)
      end

      # Returns BIP-0032 key identifier, interpreting string as binary key
      def hash160
        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers
        r = OpenSSL::Digest::SHA256.new(self).digest
        OpenSSL::Digest::RIPEMD160.new(r).digest
      end
    end
  end
end
