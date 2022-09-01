describe Derivator::Key do
  describe '#public_key_hex' do
    it 'returns public key for secp256k1' do
      key =
        Derivator::Key.from_hex(
          'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
          '',
          :secp256k1
        )
      expect(key.public_key_hex).to eq '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'
    end

    it 'returns public key for nist256p1' do
      key =
        Derivator::Key.from_hex(
          '612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2',
          '',
          :nist256p1
        )
      expect(key.public_key_hex).to eq '0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8'
    end

    it 'returns public key for ed25519' do
      key =
        Derivator::Key.from_hex(
          '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7',
          '',
          :ed25519
        )
      expect(key.public_key_hex).to eq '00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed'
    end
  end

  describe '.from_seed' do
    it 'generates master key for secp256k1' do
      key = Derivator::Key.from_seed('000102030405060708090a0b0c0d0e0f', :secp256k1)
      expect(key.fingerprint).to eq '3442193e'
      expect(key.chain_code_hex).to eq '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'
      expect(key.private_key_hex).to eq 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'
      expect(key.public_key_hex).to eq '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'
    end

    it 'generates master key for nist256p1' do
      # key = Derivator::Key.from_seed('000102030405060708090a0b0c0d0e0f', :nist256p1)
      # expect(key.fingerprint).to eq 'be6105b5'
      # expect(key.chain_code_hex).to eq 'beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea'
      # expect(key.private_key_hex).to eq '612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2'
      # expect(key.public_key_hex).to eq '0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8'

      # retry branch
      key = Derivator::Key.from_seed('a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446', :nist256p1)
      expect(key.private_key_hex).to eq '3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f'
    end

    it 'generates master key for ed25519' do
      key = Derivator::Key.from_seed('000102030405060708090a0b0c0d0e0f', :ed25519)
      expect(key.fingerprint).to eq 'ddebc675'
      expect(key.chain_code_hex).to eq '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb'
      expect(key.private_key_hex).to eq '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7'
      expect(key.public_key_hex).to eq '00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed'
    end
  end

  describe '#derive' do
    it 'derives key for secp256k1' do
      key = Derivator::Key.from_seed('000102030405060708090a0b0c0d0e0f', :secp256k1)

      derived = key.derive("m/0'")
      expect(derived.private_key_hex).to eq 'edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea'

      derived = key.derive("m/0'/1")
      expect(derived.private_key_hex).to eq '3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368'

      derived = key.derive("m/0'/1/2'")
      expect(derived.private_key_hex).to eq 'cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca'

      derived = key.derive("m/0'/1/2'/2/1000000000")
      expect(derived.private_key_hex).to eq '471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8'
    end

    it 'derives key for nist256p1' do
      key = Derivator::Key.from_seed('000102030405060708090a0b0c0d0e0f', :nist256p1)

      derived = key.derive("m/0'")
      expect(derived.private_key_hex).to eq '6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c'

      derived = key.derive("m/0'/1")
      expect(derived.private_key_hex).to eq '284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129'

      derived = key.derive("m/0'/1/2'")
      expect(derived.private_key_hex).to eq '694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7'

      derived = key.derive("m/0'/1/2'/2/1000000000")
      expect(derived.private_key_hex).to eq '21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119'

      # retry branch
      derived = key.derive("m/28578'/33941")
      expect(derived.private_key_hex).to eq '092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a'
    end

    it 'derives key for ed25519' do
      key = Derivator::Key.from_seed('000102030405060708090a0b0c0d0e0f', :ed25519)

      derived = key.derive("m/0'")
      expect(derived.private_key_hex).to eq '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3'

      derived = key.derive("m/0'/1'")
      expect(derived.private_key_hex).to eq 'b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2'

      derived = key.derive("m/0'/1'/2'/2'/1000000000'")
      expect(derived.private_key_hex).to eq '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793'
    end
  end
end
