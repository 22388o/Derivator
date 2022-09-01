# Mnemonic online playground: https://learnmeabitcoin.com/technical/mnemonic

describe Derivator::Mnemonic do
  describe '.random_bytes' do
    it 'generates 16 bytes' do
      expect(Derivator::Mnemonic.random_bytes.length).to eq 16
    end
  end

  describe '.generate' do
    it 'generates 12-word sentence' do
      result = Derivator::Mnemonic.generate
      expect(result.split(' ').length).to eq 12
    end

    it 'generates using provided bytes' do
      result = Derivator::Mnemonic.generate("p\x06\x19k\xF0\xB59\xEA\xC2\xE8fCx\xFA?\x0E")
      expect(result).to eq 'hybrid cotton foot thumb fatal voice arm art drop sick more bulb'
    end
  end

  describe '.seed' do
    it 'generates seed from mnemonic' do
      result = Derivator::Mnemonic.seed('hybrid cotton foot thumb fatal voice arm art drop sick more bulb')
      expect(result).to eq '49127d195abdcd7c9e4192f9e88d9d87ac212596316a17eaa33a6dfcefc79c6a8c3ae67d22eaf3a4bc0f145b726a0816d10f232ef54a60b178aedcfe99f8636a'
    end
  end
end
