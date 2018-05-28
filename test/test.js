/*
*
* simple tests
*
* */

var expect = chai.expect;

// timeout for asynchronous unit tests
var TIMEOUT = 120000;

var seedHex = '6fc2a047d00e5e9d883231023c92b8353085042915947d44a4ca239c9f1f7ab24cdb340dfc536430abb766f348e484bc776d120fd729292f0cdd39b2e8dc54a4'
var mnemonic = 'favorite grape end strategy item horse first source popular cactus shine child'

var seedHexToAddress = bridge.seedHexToAddress(seedHex)
console.log('seedHexToAddress: ' + seedHexToAddress)
console.log('seedHexToPubAddr: ' + JSON.stringify(bridge.seedHexToPubAddr(seedHex)))
console.log('seedHexToPrivate: ' + bridge.seedHexToPrivate(seedHex).toString('hex'))

console.log('seedHexToAddrForEtc: ' + bridge.seedHexToAddrForEtc(seedHex))
console.log('seedHexToPubAddrForEtc: ' + JSON.stringify(bridge.seedHexToPubAddrForEtc(seedHex)))
console.log('seedHexToPrivateForEtc: ' + bridge.seedHexToPrivateForEtc(seedHex).toString('hex'))

var mnemonicToAddress = bridge.seedToAddress(bridge.mnemonicToSeed(mnemonic))
console.log('mnemonicToSeed-seedToAddress: ' + mnemonicToAddress)

console.log('isValidAddress: ' + bridge.isValidAddress(seedHexToAddress))
console.log('isValidAddress: ' + bridge.isValidAddress('0x8617E340B3D01FA5F11F306F4090FD50E238070W'))
console.log('isValidChecksumAddress: ' + bridge.isValidChecksumAddress(seedHexToAddress))
console.log('isAddress: ' + bridge.isAddress('0x8617E340B3D01FA5F11F306F4090FD50E238070D'))
console.log('isAddress: ' + bridge.isAddress('0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'))
console.log('isAddress: ' + bridge.isAddress('0xd1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'))

console.log('ibanToAddress: ' + bridge.ibanToAddress('XE7338O073KYGTWWZN0F2WZ0R8PX5ZPPZS'))
console.log('addressToIban: ' + bridge.addressToIban('0x00c5496aee77c1ba1f0854206a26dda82a81d6d8'))

// get private key from keystore
var keystoreContent = '{"version":3,"id":"ce14bddd-dc5b-4f24-b94c-1bae704f6866","address":"2a055947da8ba17ac751f2aa2ea5ecfee3db8c33","Crypto":{"ciphertext":"31743384b6bede7741d90445715e95600a108edb38fd118d65e07bbf2b1e2c68","cipherparams":{"iv":"8f7b036788323944affb3ddfe286a9d4"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"d69affc8ef632ea27dedddacac00f714d17537c980193fb7dd26051d04eb4f57","n":8192,"r":8,"p":1},"mac":"581846f21e493383ae500012664d340c95dffb7897fb061519aedc9a9c96e915"}}'
var privateKey = bridge.getPrivateKeyFromKeystore('123456789', keystoreContent)
var hexPrivateKey = bridge.getHexPrivateKeyFromKeystore('123456789', keystoreContent)
console.log('get private key from keystore: ' + privateKey.toString('hex'))
console.log('get hex private key from keystore: ' + hexPrivateKey)

var publicKey = bridge.privateToPublic(privateKey);
console.log('private to public|length: ' + publicKey.toString('hex') + '|' + publicKey.length)

console.log('public to address: ' + bridge.publicToAddress(publicKey).toString('hex'))
console.log('private to address: ' + bridge.privateToAddress(privateKey).toString('hex'))

var keyPairAddrArray = bridge.getKeyPairAddrFromKeystore('123456789', keystoreContent)
console.log('getKeyPairAddrFromKeystore: ' + JSON.stringify(keyPairAddrArray))
bridge.getKeyPairAddrAsyncFromKeystore('123456789', keystoreContent, function(arr) {
    console.log('getKeyPairAddrAsyncFromKeystore: ' + JSON.stringify(arr))
})

console.log('getPubAddrFromPrivate: ' + JSON.stringify(bridge.getPubAddrFromPrivate(privateKey.toString('hex'))))


// generate eos key pair
bridge.generateEosKeyPair(function(eosKeyPair) {
    console.log('eos key pair - ' + 'publicKey: ' + eosKeyPair.publicKey + ' privateKey: ' + eosKeyPair.privateKey)
})

// build tx
console.log('buildEthTransaction:' + JSON.stringify(bridge.buildEthTransaction(privateKey.toString('hex'), 2441406250, '0xd46e8dd67c5d32be8058bb8eb970870f07244567', 0, 10e12, 30400)))


describe('seed', function() {
    it('seedHexToAddress', function() {
        expect(seedHexToAddress).to.be.equal('0x9124bae940c2321DEd56f89B7e185b8785942303');
    });

    it('seedHexToPubAddr', function() {
        expect(JSON.stringify(bridge.seedHexToPubAddr(seedHex))).to.be.equal('["e351cdae507b5c6f7d88e6966ff10d13be1668372cf1d2c60b26c851fbd41c3a6bf2452de42cdb6532aef93070760b32c0bb8f055ee258cc2973aab1d396aa53","0x9124bae940c2321DEd56f89B7e185b8785942303"]');
    });

    it('seedHexToPrivate', function() {
        expect(bridge.seedHexToPrivate(seedHex).toString('hex')).to.be.equal('f21c74d3bf4464e1472343ce5bbd62a572afcf51e36d6b65ac003fe53c3dca3d');
    });

    it('seedToAddress', function() {
        expect(bridge.seedToAddress(bridge.mnemonicToSeed(mnemonic))).to.be.equal('0x9124bae940c2321ded56f89b7e185b8785942303');
    });


    // etc
    it('seedHexToAddrForEtc', function() {
        expect(bridge.seedHexToAddrForEtc(seedHex)).to.be.equal('0x967aE99E77870e9016d46Ae70057a73E72B5Fb8a');
    });

    it('seedHexToPubAddrForEtc', function() {
        expect(JSON.stringify(bridge.seedHexToPubAddrForEtc(seedHex))).to.be.equal('["76683b3f376eed7eb2002c93413aa4d28e1d9ba83b401da9db9f6be2727525ee9b4a0c1c9f2e12f7f8891c3d4b34ebc1ba0a3c864b5aa435cfa5c9c906701c73","0x967aE99E77870e9016d46Ae70057a73E72B5Fb8a"]');
    });

    it('seedHexToPrivateForEtc', function() {
        expect(bridge.seedHexToPrivateForEtc(seedHex).toString('hex')).to.be.equal('6c768785363f14946fa042a7f280994e1e372f4a54cc97bdc2f153f475eec698');
    });
});

describe('mnemonic', function() {
    it('mnemonicToSeed', function() {
        expect(bridge.mnemonicToSeed(mnemonic).toString('hex')).to.be.equal(seedHex);
    });
});

describe('verify address', function() {
    it('isValidAddress true', function() {
        expect(bridge.isValidAddress(seedHexToAddress)).to.be.equal(true);
    });

    it('isValidAddress false', function() {
        expect(bridge.isValidAddress('0x8617E340B3D01FA5F11F306F4090FD50E238070W')).to.be.equal(false);
    });

    it('isValidChecksumAddress', function() {
        expect(bridge.isValidChecksumAddress(seedHexToAddress)).to.be.equal(true);
    });

    it('isAddress true', function() {
        expect(bridge.isAddress('0x8617E340B3D01FA5F11F306F4090FD50E238070D')).to.be.equal(true);
        expect(bridge.isAddress('0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb')).to.be.equal(true);
    });

    it('isAddress false', function() {
        expect(bridge.isAddress('0xd1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb')).to.be.equal(false);
    });
});

describe('iban', function() {
    it('ibanToAddress', function() {
        expect(bridge.ibanToAddress('XE7338O073KYGTWWZN0F2WZ0R8PX5ZPPZS')).to.be.equal('0x00c5496aEe77C1bA1f0854206A26DdA82a81D6D8');
    });

    it('addressToIban', function() {
        expect(bridge.addressToIban('0x00c5496aee77c1ba1f0854206a26dda82a81d6d8')).to.be.equal('XE7338O073KYGTWWZN0F2WZ0R8PX5ZPPZS');
    });
});

describe('import keystore', function() {
    it('getPrivateKeyFromKeystore', function() {
        expect(privateKey.toString('hex')).to.be.equal('ded772d10a77295b897824db5a4ab11c24a507a146cef2560460e491d242ccb9');
    });

    it('getHexPrivateKeyFromKeystore', function() {
        expect(hexPrivateKey).to.be.equal('ded772d10a77295b897824db5a4ab11c24a507a146cef2560460e491d242ccb9');
    });

    // synchronous
    it('getKeyPairAddrFromKeystore', function() {
        expect(JSON.stringify(keyPairAddrArray)).to.be.equal('["ded772d10a77295b897824db5a4ab11c24a507a146cef2560460e491d242ccb9","18ad4ff97d0337b6434826daa2142137afac8cb39c28485414bb77289b26dd54de8a73efd888d904267d36fc42ebe6b10db2a337a5ceb3e7972aa532cd58a817","0x2a055947dA8bA17Ac751f2Aa2EA5EcfEe3Db8C33"]');
    });
    // asynchronous
    it('getKeyPairAddrAsyncFromKeystore', function(done) {
        this.timeout(TIMEOUT);
        bridge.getKeyPairAddrAsyncFromKeystore('123456789', keystoreContent, function(arr) {
            expect(JSON.stringify(arr)).to.be.equal('["ded772d10a77295b897824db5a4ab11c24a507a146cef2560460e491d242ccb9","18ad4ff97d0337b6434826daa2142137afac8cb39c28485414bb77289b26dd54de8a73efd888d904267d36fc42ebe6b10db2a337a5ceb3e7972aa532cd58a817","0x2a055947dA8bA17Ac751f2Aa2EA5EcfEe3Db8C33"]');
            done();
        })
    });
});

describe('publicKey and privateKey', function() {
    it('privateToPublic', function() {
        expect(publicKey.toString('hex')).to.be.equal('18ad4ff97d0337b6434826daa2142137afac8cb39c28485414bb77289b26dd54de8a73efd888d904267d36fc42ebe6b10db2a337a5ceb3e7972aa532cd58a817');
    });

    it('privateToAddress', function() {
        expect(bridge.privateToAddress(privateKey).toString('hex')).to.be.equal('2a055947da8ba17ac751f2aa2ea5ecfee3db8c33');
    });

    it('publicToAddress', function() {
        expect(bridge.publicToAddress(publicKey).toString('hex')).to.be.equal('2a055947da8ba17ac751f2aa2ea5ecfee3db8c33');
    });

    it('getPubAddrFromPrivate', function() {
        expect(JSON.stringify(bridge.getPubAddrFromPrivate(privateKey.toString('hex')))).to.be.equal('["18ad4ff97d0337b6434826daa2142137afac8cb39c28485414bb77289b26dd54de8a73efd888d904267d36fc42ebe6b10db2a337a5ceb3e7972aa532cd58a817","0x2a055947dA8bA17Ac751f2Aa2EA5EcfEe3Db8C33"]');
    });
});

describe('checksum address', function() {
    it('toChecksumAddress', function() {
        expect(bridge.toChecksumAddress('0x9124bae940c2321ded56f89b7e185b8785942303')).to.be.equal('0x9124bae940c2321DEd56f89B7e185b8785942303');
        expect(bridge.toChecksumAddress('9124bae940c2321ded56f89b7e185b8785942303')).to.be.equal('0x9124bae940c2321DEd56f89B7e185b8785942303');
    });
});

describe('generate eos key pair', function() {
    it('generateEosKeyPair', function(done) {
        this.timeout(TIMEOUT);
        bridge.generateEosKeyPair(function(eosKeyPair) {
            expect(eosKeyPair).to.be.an('object');
            done();
        })
    });
});

describe('build tx', function() {
    it('buildEthTransaction', function() {
        expect(JSON.stringify(bridge.buildEthTransaction(privateKey.toString('hex'), 2441406250, '0xd46e8dd67c5d32be8058bb8eb970870f07244567', 0, 10e12, 30400))).to.be.equal('["0xbf81b5ef67cfbe58e0fc7ec1a2df997c779d40aa351453cfa642a94f0602ae91","0xf869808609184e72a0008276c094d46e8dd67c5d32be8058bb8eb970870f07244567849184e72a8026a0f42aec174f05e0f4c71ed7c4e888f834692e5eec85d82a4c88755872ce3ab24da00b22378ad5e5fe2cc109522a7fdfcfbaeffbac6360048098418de712e125bd04"]');
    });
});
