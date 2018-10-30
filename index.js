var ethereumjsUtil = require('ethereumjs-util');
var hdkey = require('ethereumjs-wallet/hdkey');
var EthereumTx = require('ethereumjs-tx');

var Web3 = require('web3');
var web3 = new Web3();

var util = require('./util');

var icap = require('ethereumjs-icap');

var keythereum = require('keythereum');

var ETHEREUM_MAINNET_PATH = "m/44'/60'/0'/0/0"; // ETH coin type is 60
var ETHEREUM_CLASSIC_MAINNET_PATH = "m/44'/61'/0'/0/0"; // ETC coin type is 61
var ETHEREUM_TESTNET_PATH = "m/44'/1'/0'/0"; // Testnet (all coins) coin type is 1

var bip39 = require('bip39');

/**
 * Mnemonic to seed
 * @param {String} mnemonic
 * @return {Buffer} seed
 */
function mnemonicToSeed(mnemonic) {
	var seed = bip39.mnemonicToSeed(mnemonic);
	return seed;
}

/**
 * Mnemonic to seedHex
 * @param {String} mnemonic
 * @return {String} seedHex
 */
function mnemonicToSeedHex(mnemonic) {
    var seed = bip39.mnemonicToSeed(mnemonic);
    return seed.toString('hex');
}

/**
 * Seed to address
 * @param {Buffer} seed
 * @param {String} [path] Derive path
 * @return {String} address
 */
function seedToAddress(seed, path) {
	var hd = hdkey.fromMasterSeed(seed);
	var wallet = hd.derivePath(path || ETHEREUM_MAINNET_PATH).getWallet();
	return ethereumjsUtil.bufferToHex(wallet.getAddress());
}

/**
 * Seed to address
 * @param {Buffer} seed
 * @return {String} address
 */
function seedToAddrForEtc(seed) {
    return seedToAddress(seed, ETHEREUM_CLASSIC_MAINNET_PATH);
}

/**
 * Seed to checksum address
 * @param {Buffer} seed
 * @param {String} [path] Derive path
 * @return {String} checksum address
 */
function seedToChecksumAddress(seed, path) {
    var hd = hdkey.fromMasterSeed(seed);
    var wallet = hd.derivePath(path || ETHEREUM_MAINNET_PATH).getWallet();
    return wallet.getChecksumAddressString();
}

/**
 * Seed to checksum address
 * @param {Buffer} seed
 * @return {String} checksum address
 */
function seedToChecksumAddrForEtc(seed) {
    return seedToChecksumAddress(seed, ETHEREUM_CLASSIC_MAINNET_PATH);
}

/**
 * Hex-encoded seed to checksum address
 * @param {String} seedHex: Hex-encoded seed
 * @return {String} checksum address
 */
function seedHexToAddress(seedHex) {
	var seed = Buffer.from(seedHex, 'hex');
	return seedToChecksumAddress(seed);
}

/**
 * Hex-encoded seed to checksum address
 * @param {String} seedHex: Hex-encoded seed
 * @return {String} checksum address
 */
function seedHexToAddrForEtc(seedHex) {
    var seed = Buffer.from(seedHex, 'hex');
    return seedToChecksumAddrForEtc(seed);
}

/**
 * Hex-encoded seed to [publicKey, address]
 * @param {String} seedHex: Hex-encoded seed
 * @param {String} [path] Derive path
 * @return {Object} [String, String]
 */
function seedHexToPubAddr(seedHex, path) {
    var seed = Buffer.from(seedHex, 'hex');
    var hd = hdkey.fromMasterSeed(seed);
    var wallet = hd.derivePath(path || ETHEREUM_MAINNET_PATH).getWallet();
    var publicKey = wallet.getPublicKey().toString('hex');
    var address = wallet.getChecksumAddressString();
    return [publicKey, address];
}

/**
 * Hex-encoded seed to [publicKey, address]
 * @param {String} seedHex: Hex-encoded seed
 * @return {Object} [String, String]
 */
function seedHexToPubAddrForEtc(seedHex) {
    return seedHexToPubAddr(seedHex, ETHEREUM_CLASSIC_MAINNET_PATH);
}

/**
 * Hex-encoded seed to privateKey
 * @param {String} seedHex: Hex-encoded seed
 * @param {String} [path] Derive path
 * @return {Buffer} privateKey
 */
function seedHexToPrivate(seedHex, path) {
    var seed = Buffer.from(seedHex, 'hex');
    var hd = hdkey.fromMasterSeed(seed);
    var wallet = hd.derivePath(path || ETHEREUM_MAINNET_PATH).getWallet();
    return wallet.getPrivateKey();
}

/**
 * Hex-encoded seed to Hex-encoded privateKey
 * @param {String} seedHex: Hex-encoded seed
 * @param {String} [path] Derive path
 * @return {String} Hex-encoded privateKey
 */
function seedHexToPrivateHex(seedHex, path) {
    var seed = Buffer.from(seedHex, 'hex');
    var hd = hdkey.fromMasterSeed(seed);
    var wallet = hd.derivePath(path || ETHEREUM_MAINNET_PATH).getWallet();
    return wallet.getPrivateKeyString();
}

/**
 * Hex-encoded seed to privateKey
 * @param {String} seedHex: Hex-encoded seed
 * @return {Buffer} privateKey
 */
function seedHexToPrivateForEtc(seedHex) {
    return seedHexToPrivate(seedHex, ETHEREUM_CLASSIC_MAINNET_PATH);
}

/**
 * verify address
 * @param {String} address
 * @return {Boolean}
 */
function isValidAddress(address) {
	return ethereumjsUtil.isValidAddress(address);
}

/**
 * verify checksum address
 * @param {String} address
 * @return {Boolean}
 */
function isValidChecksumAddress(address) {
	return ethereumjsUtil.isValidChecksumAddress(address);
}

/**
 * Checks if the given string is an address
 *
 * @method isAddress
 * @param {String} address the given HEX adress
 * @return {Boolean}
 */
function isAddress(address) {
    return web3.isAddress(address);
}

/**
 * iban to address
 * @param {String} iban
 * @return {String} address
 */
function ibanToAddress(iban) {
    return ethereumjsUtil.toChecksumAddress(icap.toAddress(iban));
}

/**
 * address to iban
 * @param {String} address
 * @return {String} iban
 */
function addressToIban(address) {
    return icap.fromAddress(address, false, true);
}

/**
 * build a eth transaction
 * @param {Number|String} amountWei
 * @param {String} addressTo
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} customData
 * @param {Number} [chainId=1] chainId=61 for etc
 * @param {String} privateKey: Hex-encoded
 * @return {Array} [txid, serializedTx]
 */
function buildEthTransaction(privateKey, amountWei, addressTo, nonce, gasPrice, gasLimit, customData, chainId) {
    privateKey = Buffer.from(privateKey, 'hex');
    var transaction = new EthereumTx({
        nonce: web3.toHex(nonce),
        gasPrice: web3.toHex(gasPrice),
        gasLimit: web3.toHex(gasLimit),
        to: addressTo,
        value: web3.toHex(amountWei),
        data: (customData && customData.length > 0) ? customData : '0x',
        chainId: chainId || 1
    });
    transaction.sign(privateKey);
    var txid = ('0x' + transaction.hash().toString('hex'));
    var serializedTx = ('0x' + transaction.serialize().toString('hex'));

    console.log('buildEthTransaction-transaction: ' + JSON.stringify(transaction));

    return [txid, serializedTx];
}

/**
 * build a eth transaction by Hex-encoded seed
 * @param {String} seedHex: Hex-encoded seed
 * @param {Number|String} amountWei
 * @param {String} addressTo
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} customData
 * @return {Array} [txid, serializedTx]
 */
function buildEthTxBySeedHex(seedHex, amountWei, addressTo, nonce, gasPrice, gasLimit, customData) {
    var privateKey = seedHexToPrivate(seedHex);
    return buildEthTransaction(privateKey, amountWei, addressTo, nonce, gasPrice, gasLimit, customData);
}

/**
 * build a etc transaction by Hex-encoded privateKey
 * @param {String} privateKey: Hex-encoded
 * @param {Number|String} amountWei
 * @param {String} addressTo
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} customData
 * @return {Array} [txid, serializedTx]
 */
function buildEtcTransaction(privateKey, amountWei, addressTo, nonce, gasPrice, gasLimit, customData) {
    return buildEthTransaction(privateKey, amountWei, addressTo, nonce, gasPrice, gasLimit, customData, 61);
}

/**
 * build a etc transaction by Hex-encoded seed
 * @param {String} seedHex: Hex-encoded seed
 * @param {Number|String} amountWei
 * @param {String} addressTo
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} customData
 * @return {Array} [txid, serializedTx]
 */
function buildEtcTxBySeedHex(seedHex, amountWei, addressTo, nonce, gasPrice, gasLimit, customData) {
    var privateKey = seedHexToPrivate(seedHex);
    return buildEthTransaction(privateKey, amountWei, addressTo, nonce, gasPrice, gasLimit, customData, 61);
}

/**
 * build a token transaction
 * @param {String} privateKey: Hex-encoded
 * @param {Number|String} amountWei
 * @param {String} addressTo
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} contractAddress
 * @return {Array} [txid, serializedTx]
 */
function buildTokenTransaction(amountWei, addressTo, nonce, contractAddress, gasLimit, gasPrice, privateKey) {
    privateKey = Buffer.from(privateKey, 'hex');
    var data = util.createTokenData(web3, amountWei, addressTo);
    //  console.log('Data', data);
    var raw = util.mapEthTransaction(web3, contractAddress, '0', nonce, gasPrice, gasLimit, data);
    // console.log(raw);
    var transaction = new EthereumTx(raw);
    //console.log(transaction);
    transaction.sign(privateKey);
    var serializedTx = ('0x' + transaction.serialize().toString('hex'));
    var txid = ('0x' + transaction.hash().toString('hex'));
    return [txid, serializedTx];
}

/**
 * build a token transaction by Hex-encoded seed
 * @param {String} seedHex: Hex-encoded seed
 * @param {Number|String} amountWei
 * @param {String} addressTo
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} contractAddress
 * @return {Array} [txid, serializedTx]
 */
function buildTokenTxBySeedHex(seedHex, amountWei, addressTo, nonce, contractAddress, gasLimit, gasPrice) {
    var privateKey = seedHexToPrivate(seedHex);
    return buildTokenTransaction(amountWei, addressTo, nonce, contractAddress, gasLimit, gasPrice, privateKey);
}

/**
 * build a eos map transaction
 * @param {String} privateKey: Hex-encoded
 * @param {String} eosPublicKey
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} contractAddress
 * @return {Array} [txid, serializedTx]
 */
function buildMapEosTransaction(eosPublicKey, nonce, contractAddress, gasLimit, gasPrice, privateKey) {
    privateKey = Buffer.from(privateKey, 'hex');
    var data = util.getTxData('register', ['string'], [eosPublicKey]);
    //  console.log('Data', data);
    var raw = util.mapEthTransaction(web3, contractAddress, '0', nonce, gasPrice, gasLimit, data);
    // console.log(raw);
    var transaction = new EthereumTx(raw);
    //console.log(transaction);
    transaction.sign(privateKey);
    var serializedTx = ('0x' + transaction.serialize().toString('hex'));
    var txid = ('0x' + transaction.hash().toString('hex'));
    return [txid, serializedTx];
}

/**
 * build a eos map transaction by Hex-encoded seed
 * @param {String} seedHex: Hex-encoded seed
 * @param {String} eosPublicKey
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} contractAddress
 * @return {Array} [txid, serializedTx]
 */
function buildMapEosTxBySeedHex(seedHex, eosPublicKey, nonce, contractAddress, gasLimit, gasPrice) {
    var privateKey = seedHexToPrivate(seedHex);
    return buildMapEosTransaction(eosPublicKey, nonce, contractAddress, gasLimit, gasPrice, privateKey);
}

/**
 * Generate eos keyPair.
 * @param {Function} cb is a Callback function, function params is {publicKey, privateKey}.
 */
function generateEosKeyPair(cb) {
    util.generateEosKeyPair(cb);
}

/**
 * Recover plaintext private key from secret-storage key object.
 * @param {string} password.
 * @param {string} keystoreContent: keystore file content.
 * @return {Buffer} Plaintext private key.
 */
function getPrivateKeyFromKeystore (password, keystoreContent) {
    var keyObject = JSON.parse(keystoreContent);
    return keythereum.recover(password, keyObject);
}

/**
 * Recover plaintext private key from secret-storage key object.
 * @param {string} password.
 * @param {string} keystoreContent: keystore file content.
 * @return {String} Plaintext private key.
 */
function getHexPrivateKeyFromKeystore (password, keystoreContent) {
    return getPrivateKeyFromKeystore (password, keystoreContent).toString('hex');
}

/**
 * Recover mnemonic from secret-storage mnemonic object.
 * @param {string} password.
 * @param {string} mnemonicStoreContent: mnemonicStore file content.
 * @return {String} mnemonic.
 */
function getMnemonicFromMnemonicStore (password, mnemonicStoreContent) {
    return getPrivateKeyFromKeystore (password, mnemonicStoreContent).toString();
}

/**
 * Returns the ethereum public key of a given private key
 * @param {Buffer} privateKey A private key must be 256 bits wide
 * @return {Buffer}
 */
function privateToPublic(privateKey) {
    return ethereumjsUtil.privateToPublic(privateKey);
}

/**
 * Returns the ethereum address of a given public key.
 * Accepts "Ethereum public keys" and SEC1 encoded keys.
 * @param {Buffer} pubKey The two points of an uncompressed key, unless sanitize is enabled
 * @param {Boolean} [sanitize=false] Accept public keys in other formats
 * @return {Buffer}
 */
function publicToAddress(pubKey, sanitize) {
    return ethereumjsUtil.publicToAddress(pubKey, sanitize);
}

/**
 * Returns the ethereum address of a given private key
 * @param {Buffer} privateKey A private key must be 256 bits wide
 * @return {Buffer}
 */
function privateToAddress(privateKey) {
    return ethereumjsUtil.privateToAddress(privateKey);
}

/**
 * Get privateKey&publicKey&address from secret-storage keystore file.
 * @param {string} password.
 * @param {string} keystoreContent: keystore file content.
 * @return {Array} [privateKey, publicKey, address].
 */
function getKeyPairAddrFromKeystore (password, keystoreContent) {
    var privateKey = getPrivateKeyFromKeystore(password, keystoreContent);
    var publicKey = privateToPublic(privateKey);
    var address = "0x" + privateToAddress(privateKey).toString('hex');
    address = ethereumjsUtil.toChecksumAddress(address);

    return [privateKey.toString('hex'), publicKey.toString('hex'), address]
}

/**
 * Get privateKey&publicKey&address from secret-storage keystore file.
 * @param {string} password.
 * @param {string} keystoreContent: keystore file content.
 * @param {Function} cb is a Callback function, function params is [privateKey, publicKey, address].
 * @return {Array} [privateKey, publicKey, address].
 */
function getKeyPairAddrAsyncFromKeystore (password, keystoreContent, cb) {
    var keyObject = JSON.parse(keystoreContent);
    // Asynchronous
    keythereum.recover(password, keyObject, function (privateKey) {
        // do stuff
        var publicKey = privateToPublic(privateKey);
        var address = "0x" + privateToAddress(privateKey).toString('hex');
        address = ethereumjsUtil.toChecksumAddress(address);

        cb && cb([privateKey.toString('hex'), publicKey.toString('hex'), address]);
    });
}

/**
 * Get publicKey&address from privateKey.
 * @param {String|Buffer} privateKey ECDSA private key.
 * @return {Array} [publicKey, address].
 */
function getPubAddrFromPrivate(privateKey) {
    if((typeof privateKey === 'string') && (privateKey.indexOf('0x') === 0)) {
        privateKey = privateKey.substr(2);
    }

    var privateKeyBuffer = keythereum.str2buf(privateKey);
    if (privateKeyBuffer.length < 32) {
        privateKeyBuffer = Buffer.concat([
            Buffer.alloc(32 - privateKeyBuffer.length, 0),
            privateKeyBuffer
        ]);
    }

    var publicKey = privateToPublic(privateKeyBuffer);
    var address = "0x" + privateToAddress(privateKeyBuffer).toString('hex');
    address = ethereumjsUtil.toChecksumAddress(address);

    return [publicKey.toString('hex'), address];
}

/**
 * Returns a checksummed address
 * @param {String} address
 * @return {String}
 */
function toChecksumAddress(address) {
    return ethereumjsUtil.toChecksumAddress(address);
}

/**
 * build a deploy contract transaction
 * @param {String} constructorArgs: '{owners:['0x123...','0x123...','0x123...'], required: 2}' for 2 of 3
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} privateKey: Hex-encoded
 * @return {Array} [txid, serializedTx]
 */
function buildDeployContractTx(constructorArgs, nonce, gasLimit, gasPrice, privateKey) {
    constructorArgs = JSON.parse(constructorArgs);

    privateKey = Buffer.from(privateKey, 'hex');
    var data = util.getDeployContractTxData(web3, [constructorArgs.owners, constructorArgs.required]);
    console.log('buildDeployContractTx data', data);
    var transaction = new EthereumTx({
        nonce: web3.toHex(nonce),
        gasPrice: web3.toHex(gasPrice),
        gasLimit: web3.toHex(gasLimit),
        value: 0,
        data: data,
        chainId: 1
    });
    //console.log(transaction);
    transaction.sign(privateKey);
    var serializedTx = ('0x' + transaction.serialize().toString('hex'));
    var txid = ('0x' + transaction.hash().toString('hex'));
    return [txid, serializedTx];
}

/**
 * build a deploy contract transaction by Hex-encoded seed
 * @param {String} constructorArgs: '{owners:['0x123...','0x123...','0x123...'], required: 2}' for 2 of 3
 * @param {Number|String} nonce
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} seedHex: Hex-encoded seed
 * @return {Array} [txid, serializedTx]
 */
function buildDeployContractTxBySeedHex(constructorArgs, nonce, gasLimit, gasPrice, seedHex) {
    var privateKey = seedHexToPrivate(seedHex);
    return buildDeployContractTx(constructorArgs, nonce, gasLimit, gasPrice, privateKey);
}


/**
 * build a transaction for calling contract method
 * @param {string} funcName
 * @param {Array<string>} types, a array of func params type, eg:[ 'uint', 'uint32[]', 'bytes10', 'bytes' ]
 * @param {Array<type>} values, a array of func params value, eg: [ 0x123, [ 0x456, 0x789 ], '1234567890', 'Hello, world!' ]
 * @param {Number|String} nonce
 * @param {String} contractAddress
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} privateKey: Hex-encoded
 * @return {Array} [txid, serializedTx]
 */
function buildCallContractMdTx(funcName, types, values, nonce, contractAddress, gasLimit, gasPrice, privateKey) {
    privateKey = Buffer.from(privateKey, 'hex');
    var data = util.getTxData(funcName, types, values);
    //  console.log('Data', data);
    var raw = util.mapEthTransaction(web3, contractAddress, '0', nonce, gasPrice, gasLimit, data);
    // console.log(raw);
    var transaction = new EthereumTx(raw);
    //console.log(transaction);
    transaction.sign(privateKey);
    var serializedTx = ('0x' + transaction.serialize().toString('hex'));
    var txid = ('0x' + transaction.hash().toString('hex'));
    return [txid, serializedTx];
}

/**
 * build a transaction for calling multisig contract method
 * @param {String} destination
 * @param {Number|String} value
 * @param {String} vs: Array of multisig v
 * @param {String} rs: Array of multisig r
 * @param {String} ss: Array of multisig s
 * @param {Number|String} nonce
 * @param {String} contractAddress
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} privateKey: Hex-encoded
 * @return {Array} [txid, serializedTx]
 */
function buildCallMSContractMdTx(destination, value, vs, rs, ss, nonce, contractAddress, gasLimit, gasPrice, privateKey) {
    vs = JSON.parse(vs);
    rs = JSON.parse(rs);
    ss = JSON.parse(ss);

    var funcName = 'spend';
    var types = ['address', 'uint256', 'uint8[]', 'bytes32[]', 'bytes32[]'];
    var values = [destination, web3.toHex(value), vs, rs, ss];
    return buildCallContractMdTx(funcName, types, values, nonce, contractAddress, gasLimit, gasPrice, privateKey);
}

/**
 * build a transaction for calling multisig contract method by Hex-encoded seed
 * @param {String} destination
 * @param {Number|String} value
 * @param {String} vs: Array of multisig v
 * @param {String} rs: Array of multisig r
 * @param {String} ss: Array of multisig s
 * @param {Number|String} nonce
 * @param {String} contractAddress
 * @param {Number|String} gasPrice
 * @param {Number|String} gasLimit
 * @param {String} seedHex: Hex-encoded seed
 * @return {Array} [txid, serializedTx]
 */
function buildCallMSContractMdTxBySeedHex(destination, value, vs, rs, ss, nonce, contractAddress, gasLimit, gasPrice, seedHex) {
    var privateKey = seedHexToPrivate(seedHex);
    return buildCallMSContractMdTx(destination, value, vs, rs, ss, nonce, contractAddress, gasLimit, gasPrice, privateKey);
}

/**
 * generate multisig
 * @param {Number|String} spendNonce
 * @param {String} contractAddress
 * @param {Number|String} value
 * @param {String} destination
 * @param {String} privateKey: Hex-encoded
 * @return {Array} multisig [v, r, s]
 */
function generateMultiSig(spendNonce, contractAddress, value, destination, privateKey) {
    privateKey = Buffer.from(privateKey, 'hex');
    var msgHex = '0x' + web3.padLeft(web3.toHex(spendNonce).substr(2), 64) + web3.toHex(contractAddress).substr(2) + web3.padLeft(web3.toHex(value).substr(2), 64) + web3.toHex(destination).substr(2);
    console.log('msgHex: ' + msgHex);
    var msgHash = ethereumjsUtil.hashPersonalMessage(ethereumjsUtil.sha3(msgHex));
    console.log('msgHash: ' + msgHash.toString('hex'));
    var sig = ethereumjsUtil.ecsign(msgHash, privateKey);

    return [sig.v-27, '0x'+sig.r.toString('hex'), '0x'+sig.s.toString('hex')];
}

/**
 * generate multisig by Hex-encoded seed
 * @param {Number|String} spendNonce
 * @param {String} contractAddress
 * @param {Number|String} value
 * @param {String} destination
 * @param {String} seedHex: Hex-encoded seed
 * @return {Array} multisig [v, r, s]
 */
function generateMultiSigBySeedHex(spendNonce, contractAddress, value, destination, seedHex) {
    var privateKey = seedHexToPrivate(seedHex);
    return generateMultiSig(spendNonce, contractAddress, value, destination, privateKey);
}

/**
 * generate secret-storage mnemonic object.
 * @param {String} password.
 * @param {String} mnemonic.
 * @return {Object} mnemonic store.
 */
function generateMnemonicStore(password, mnemonic) {
    var params = { keyBytes: 32, ivBytes: 16 };
    var dk = keythereum.create(params);

    var options = {
        kdf: "scrypt",
        cipher: "aes-128-ctr",
        kdfparams: {
            "dklen": 32,
            "n": 262144,
            "p": 1,
            "r": 8
        }
    };

    var mnemonicObject = keythereum.dumpForMnemonic(password, mnemonic, dk.salt, dk.iv, options);
    console.log('generateMnemonicStore: ' + JSON.stringify(mnemonicObject));

    return JSON.stringify(mnemonicObject);
}


module.exports = {
    mnemonicToSeed: mnemonicToSeed,
    mnemonicToSeedHex: mnemonicToSeedHex,
    seedToAddress: seedToAddress,
    seedToChecksumAddress: seedToChecksumAddress,
    seedHexToAddress: seedHexToAddress,
    seedHexToPubAddr: seedHexToPubAddr,
    seedHexToPrivate: seedHexToPrivate,
    seedHexToPrivateHex: seedHexToPrivateHex,
    isValidAddress: isValidAddress,
    isValidChecksumAddress: isValidChecksumAddress,
    isAddress: isAddress,
    buildEthTransaction: buildEthTransaction,
    buildEthTxBySeedHex: buildEthTxBySeedHex,
    buildTokenTransaction: buildTokenTransaction,
    buildTokenTxBySeedHex: buildTokenTxBySeedHex,
    buildMapEosTransaction: buildMapEosTransaction,
    buildMapEosTxBySeedHex: buildMapEosTxBySeedHex,
    generateEosKeyPair: generateEosKeyPair,
    ibanToAddress: ibanToAddress,
    addressToIban: addressToIban,
    getPrivateKeyFromKeystore: getPrivateKeyFromKeystore,
    getHexPrivateKeyFromKeystore: getHexPrivateKeyFromKeystore,
    privateToPublic: privateToPublic,
    publicToAddress: publicToAddress,
    privateToAddress: privateToAddress,
    getKeyPairAddrFromKeystore: getKeyPairAddrFromKeystore,
    getKeyPairAddrAsyncFromKeystore: getKeyPairAddrAsyncFromKeystore,
    getPubAddrFromPrivate: getPubAddrFromPrivate,
    toChecksumAddress: toChecksumAddress,
    seedToAddrForEtc: seedToAddrForEtc,
    seedToChecksumAddrForEtc: seedToChecksumAddrForEtc,
    seedHexToPubAddrForEtc: seedHexToPubAddrForEtc,
    seedHexToPrivateForEtc: seedHexToPrivateForEtc,
    seedHexToAddrForEtc: seedHexToAddrForEtc,
    buildEtcTransaction: buildEtcTransaction,
    buildEtcTxBySeedHex: buildEtcTxBySeedHex,
    buildDeployContractTx: buildDeployContractTx,
    buildDeployContractTxBySeedHex: buildDeployContractTxBySeedHex,
    buildCallMSContractMdTx: buildCallMSContractMdTx,
    buildCallMSContractMdTxBySeedHex: buildCallMSContractMdTxBySeedHex,
    generateMultiSig: generateMultiSig,
    generateMultiSigBySeedHex: generateMultiSigBySeedHex,
    getMnemonicFromMnemonicStore: getMnemonicFromMnemonicStore,
    generateMnemonicStore: generateMnemonicStore
};

