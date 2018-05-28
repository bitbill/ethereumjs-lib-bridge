/**
 * utils for eth wallet
 *
 */

const abi = require('ethereumjs-abi');
const eos_ecc = require('eosjs-ecc');

// create erc20 token data
let createTokenData = function(web3, amount, address) {
    //send max for tokens issue use big number library to parse value amount
    let ABI = web3.toBigNumber(amount, 10).toString(16); //amount;//parseInt(amount).toString(16);
    while (ABI.length < 64)
        ABI = '0' + ABI;
    address = address.substr(2);
    while (address.length < 64)
        address = '0' + address;
    let ethData = address + ABI;
    return '0xa9059cbb' + ethData;
};

let mapEthTransaction = function(web3, addressTo, amount, nonce, gasPrice, gasLimit, data) {
    return {
        nonce: web3.toHex(nonce),
        gasPrice: web3.toHex(gasPrice),
        gasLimit: web3.toHex(gasLimit),
        to: addressTo,
        value: web3.toHex(amount),
        data: data,
        chainId: 1
    };
};

/**
 * generate a private and public key pair for the EOS chain
 *
 * @param {Function} cb is a Callback function, function params is {publicKey, privateKey}.
 */
let generateEosKeyPair = function(cb) {
    eos_ecc.randomKey().then(privateKey => {
        let publicKey = eos_ecc.privateToPublic(privateKey)

        // console.log(privateKey + ': ' + publicKey)
        let eosKeyPair = {
            publicKey,
            privateKey,
        }
        cb && cb(eosKeyPair)
    })
};

/**
 * get tx data
 *
 * @param {string} funcName
 * @param {Array<string>} types, a array of func params type, eg:[ 'uint', 'uint32[]', 'bytes10', 'bytes' ]
 * @param {Array<type>} values, a array of func params value, eg: [ 0x123, [ 0x456, 0x789 ], '1234567890', 'Hello, world!' ]
 * @returns {string}
 */
let getTxData = function(funcName, types, values) {
    return '0x' + abi.methodID(funcName, types).toString('hex')
        + abi.rawEncode(types, values).toString('hex');
};

module.exports = {
    createTokenData: createTokenData,
    mapEthTransaction: mapEthTransaction,
    getTxData: getTxData,
    generateEosKeyPair: generateEosKeyPair
};