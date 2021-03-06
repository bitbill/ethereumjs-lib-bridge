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
console.log('seedHexToPrivateHex: ' + bridge.seedHexToPrivateHex(seedHex))

console.log('seedHexToAddrForEtc: ' + bridge.seedHexToAddrForEtc(seedHex))
console.log('seedHexToPubAddrForEtc: ' + JSON.stringify(bridge.seedHexToPubAddrForEtc(seedHex)))
console.log('seedHexToPrivateForEtc: ' + bridge.seedHexToPrivateForEtc(seedHex).toString('hex'))

console.log('isValidAddress: ' + bridge.isValidAddress(seedHexToAddress))
console.log('isValidAddress: ' + bridge.isValidAddress('0x8617E340B3D01FA5F11F306F4090FD50E238070W'))
console.log('isValidChecksumAddress: ' + bridge.isValidChecksumAddress(seedHexToAddress))
console.log('isAddress: ' + bridge.isAddress('0x8617E340B3D01FA5F11F306F4090FD50E238070D'))
console.log('isAddress: ' + bridge.isAddress('0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'))
console.log('isAddress: ' + bridge.isAddress('0xd1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'))

console.log('ibanToAddress: ' + bridge.ibanToAddress('XE7338O073KYGTWWZN0F2WZ0R8PX5ZPPZS'))
console.log('addressToIban: ' + bridge.addressToIban('0x00c5496aee77c1ba1f0854206a26dda82a81d6d8'))

// console.log('generateMnemonicStore: ' + bridge.generateMnemonicStore('123456', mnemonic))
// console.log('getMnemonicFromMnemonicStore: ' + bridge.getMnemonicFromMnemonicStore('123456', '{"crypto":{"cipher":"aes-128-ctr","ciphertext":"330905d7be74c66204627bbc63e9f3632d114e7ad0146f2abf9127ed4b20c3b0e265523ec0e849dad48d897e97000ae652f8e293cdf5fd4d682381a83bc68def0c4004dfea22ab38346aa469722a","cipherparams":{"iv":"0e2743952791d2c013595dd6562e395a"},"mac":"99d8089db2b8420427257fc2fbae5972e516bfa092adf228258dbadf46bf03d4","kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"r":8,"p":1,"salt":"8770de06f6f1c588012196a22c77a9198ba1ba7e8924f5622c8341c0af7f61a1"}},"id":"a46487ec-96cc-4b5d-a729-5016a0407584","version":3}'))

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
console.log('buildEthTransaction:' + JSON.stringify(bridge.buildEthTransaction(privateKey.toString('hex'), 1e+17, '0xd46e8dd67c5d32be8058bb8eb970870f07244567', 0, 1e+12, 21000)))
console.log('buildEtcTxBySeedHex:' + JSON.stringify(bridge.buildEtcTxBySeedHex(seedHex, 1e+17, '0xd46e8dd67c5d32be8058bb8eb970870f07244567', 0, 1e+12, 21000)))
console.log('buildDeployContractTx:' + JSON.stringify(bridge.buildDeployContractTx('{"owners":["0x1E335392255A738Eb98b71d24445f54488Cb2CDB","0x097bEA5e8032066457B516abbAD59B67D1096405","0x0298E91A39E001626d33cCF3e62b00F35f74055e"], "required":2}', 0, 1e+12, 21000, privateKey.toString('hex'))))

console.log('generateMultiSig: ' + JSON.stringify(bridge.generateMultiSig(123456789,'0xcbbe6ec46746218a5bed5b336ab86a0a22804d39','0x123456','0xB8c77482e45F1F44dE1745F52C74426C631bDD52','ded772d10a77295b897824db5a4ab11c24a507a146cef2560460e491d242ccb9')))

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

    it('seedHexToPrivateHex', function() {
        expect(bridge.seedHexToPrivateHex(seedHex)).to.be.equal('0xf21c74d3bf4464e1472343ce5bbd62a572afcf51e36d6b65ac003fe53c3dca3d');
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

describe('mnemonic store', function() {
    it('generateMnemonicStore getMnemonicFromMnemonicStore', function() {
        this.timeout(TIMEOUT);
        var mnemonicStore = bridge.generateMnemonicStore('123456', mnemonic);
        expect(bridge.getMnemonicFromMnemonicStore('123456', mnemonicStore)).to.be.equal(mnemonic);
    });
});

describe('build tx', function() {
    it('buildEthTransaction', function() {
        expect(JSON.stringify(bridge.buildEthTransaction(privateKey.toString('hex'), 1e+17, '0xd46e8dd67c5d32be8058bb8eb970870f07244567', 0, 1e+12, 21000))).to.be.equal('["0xa67de6ed283816afd3f15fdad734465f483f68567970f476aad22784d64301e4","0xf86c8085e8d4a5100082520894d46e8dd67c5d32be8058bb8eb970870f0724456788016345785d8a00008025a027bec1e14099ff2e5773af7d576e36cd530df800e3fd7d5f70d0b1ac87d0b6f7a036086098ce451b2cfd4b2e3af0b010b19e3f909477eab25abbfde500ccd1f6db"]');
    });

    it('buildEtcTxBySeedHex', function() {
        expect(JSON.stringify(bridge.buildEtcTxBySeedHex(seedHex, 1e+17, '0xd46e8dd67c5d32be8058bb8eb970870f07244567', 0, 1e+12, 21000))).to.be.equal('["0xb8824f4d405804ffaab09a86a3b400b4433c55469dbbcc035d44714c5b4d27fb","0xf86d8085e8d4a5100082520894d46e8dd67c5d32be8058bb8eb970870f0724456788016345785d8a000080819ea0405a9d629b7e7f240d5b44d1752e5fa93800d0c47baaa445d0a7ea19bd8bac19a0774a2e60fbd276c8218bbec21cb7e392796a25f9ec8699423cf23b598bac89ff"]');
    });
});


describe('multiple signature', function() {
    it('generateMultiSig', function() {
        expect(JSON.stringify(bridge.generateMultiSig(123456789,'0xcbbe6ec46746218a5bed5b336ab86a0a22804d39','0x123456','0xB8c77482e45F1F44dE1745F52C74426C631bDD52','ded772d10a77295b897824db5a4ab11c24a507a146cef2560460e491d242ccb9'))).to.be.equal('[0,"0x5e97da389bed7bd3244da8f73c8abe535405acd291284e19a468e851f944fba4","0x101bc448340aaf2ac43af33b80607f6ea375432ef650e352d982322aceeafe58"]');
    });

    it('generateMultiSigBySeedHex', function() {
        expect(JSON.stringify(bridge.generateMultiSigBySeedHex(123456789,'0xcbbe6ec46746218a5bed5b336ab86a0a22804d39','0x123456','0xB8c77482e45F1F44dE1745F52C74426C631bDD52', seedHex))).to.be.equal('[1,"0x885302487675fdc0972775a0215b5f1c4a34a6f22113cd74d65881ca213a32d3","0x22874fdd4d29758fc9474026ce52cdd77231f81ed789d382cd9211a04716bd6e"]');
    });

    it('buildDeployContractTx', function() {
        expect(bridge.buildDeployContractTx('{"owners":["0x1E335392255A738Eb98b71d24445f54488Cb2CDB", "0x097bEA5e8032066457B516abbAD59B67D1096405", "0x0298E91A39E001626d33cCF3e62b00F35f74055e"], "required":2}', 0, 1e+12, 21000, privateKey.toString('hex'))[0]).to.be.equal('0xfa0627cfb6e7c2ac8b28928dcb6b15d1121c1cd0032b042983f591e6f1e0adfd');
    });

    it('buildDeployContractTxBySeedHex', function() {
        expect(bridge.buildDeployContractTxBySeedHex('{"owners":["0x1E335392255A738Eb98b71d24445f54488Cb2CDB", "0x097bEA5e8032066457B516abbAD59B67D1096405", "0x0298E91A39E001626d33cCF3e62b00F35f74055e"], "required":2}', 0, 1e+12, 21000, seedHex)[0]).to.be.equal('0x36b99a8a702a7cb65ba58f39e7e307f4d9261a4aefa50981bed9cb826f2175bb');
    });

    it('buildCallMSContractMdTx', function() {
        expect(bridge.buildCallMSContractMdTx('0x4Db4504a834abc823Bd6b1Db010fD6e7f3C4aB85', '10000000000000000', '[0,1]', '["0x59aa0ed94154a9256595beecd9646f902564ba6ec0945622ad103b4849f98e98","0x79eca97e44c2c1b775ef7cc4a16ba23a023a40d17ee969cce5e6ed90ab5b035b"]', '["0x5164fd1d70593499b3d829a256e0ab2328d21fb5fa7f48cc46b1739fbf6192fa","0x4d814bbf86b32b70e078f8d3c110e9963011b52f8c3f397826f55c900d9455b1"]', 211, '0x604650973221dc9f0da94fbf5fdbdfaa70e08f4c', 800000, '15000000000', hexPrivateKey)[0]).to.be.equal('0x10a27c24f0962733ce6ee0cf59e51471f1535435f6c0dd21402aac66fa846e32');
    });

    it('buildCallMSContractMdTxBySeedHex', function() {
        expect(bridge.buildCallMSContractMdTxBySeedHex('0x4Db4504a834abc823Bd6b1Db010fD6e7f3C4aB85', '10000000000000000', '[0,1]', '["0x59aa0ed94154a9256595beecd9646f902564ba6ec0945622ad103b4849f98e98","0x79eca97e44c2c1b775ef7cc4a16ba23a023a40d17ee969cce5e6ed90ab5b035b"]', '["0x5164fd1d70593499b3d829a256e0ab2328d21fb5fa7f48cc46b1739fbf6192fa","0x4d814bbf86b32b70e078f8d3c110e9963011b52f8c3f397826f55c900d9455b1"]', 211, '0x604650973221dc9f0da94fbf5fdbdfaa70e08f4c', 800000, '15000000000', seedHex)[0]).to.be.equal('0x244cdcc44095c8498e631d17ce8f90566fdb7c66edd2816906b58258d70f5ea9');
    })
});
