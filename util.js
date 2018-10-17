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

/**
 *
 * get deploy contract tx data
 * @returns {string}
 *
 */
let getDeployContractTxData = function(web3, args) {
    let contractData = {
        bytecode: '6080604052600060035534801561001557600080fd5b50604051610c76380380610c7683398101806040528101908080518201929190602001805190602001909291905050506000825182600982118061005857508181115b806100635750600081145b8061006e5750600082145b1561007857600080fd5b600092505b84518310156101a657600080868581518110151561009757fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16806101215750600085848151811015156100ff57fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff16145b1561012b57600080fd5b6001600080878681518110151561013e57fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff021916908315150217905550828060010193505061007d565b84600190805190602001906101bc9291906101ce565b5083600281905550505050505061029b565b828054828255906000526020600020908101928215610247579160200282015b828111156102465782518260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550916020019190600101906101ee565b5b5090506102549190610258565b5090565b61029891905b8082111561029457600081816101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690555060010161025e565b5090565b90565b6109cc806102aa6000396000f300608060405260043610610078576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680631398a5f6146100c857806385b2566a146100f3578063a0e67e2b14610209578063c6a2a9f114610275578063d0590bad146102a0578063d74f8edd14610309575b7fc4c14883ae9fd8e26d5d59e3485ed29fd126d781d7e498a4ca5c54c8268e49363073ffffffffffffffffffffffffffffffffffffffff16316040518082815260200191505060405180910390a1005b3480156100d457600080fd5b506100dd610334565b6040518082815260200191505060405180910390f35b3480156100ff57600080fd5b50610207600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919080359060200190820180359060200190808060200260200160405190810160405280939291908181526020018383602002808284378201915050505050509192919290803590602001908201803590602001908080602002602001604051908101604052809392919081815260200183836020028082843782019150505050505091929192908035906020019082018035906020019080806020026020016040519081016040528093929190818152602001838360200280828437820191505050505050919291929050505061033e565b005b34801561021557600080fd5b5061021e610441565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b83811015610261578082015181840152602081019050610246565b505050509050019250505060405180910390f35b34801561028157600080fd5b5061028a6104cf565b6040518082815260200191505060405180910390f35b3480156102ac57600080fd5b506102eb600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506104d9565b60405180826000191660001916815260200191505060405180910390f35b34801561031557600080fd5b5061031e6105c9565b6040518082815260200191505060405180910390f35b6000600254905090565b833073ffffffffffffffffffffffffffffffffffffffff16311015151561036457600080fd5b61037185858585856105ce565b151561037c57600080fd5b6001600354016003819055508473ffffffffffffffffffffffffffffffffffffffff166108fc859081150290604051600060405180830381858888f193505050501580156103ce573d6000803e3d6000fd5b507fd3eec71143c45f28685b24760ea218d476917aa0ac0392a55e5304cef40bd2b68585604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019250505060405180910390a15050505050565b606060018054806020026020016040519081016040528092919081815260200182805480156104c557602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001906001019080831161047b575b5050505050905090565b6000600354905090565b6000803073ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff161415151561051757600080fd5b600354308486604051808581526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018381526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401945050505050604051809103902090508091505092915050565b600981565b60008060606000855187511415156105e557600080fd5b845186511415156105f557600080fd5b60018054905087511115151561060a57600080fd5b60025487511015151561061c57600080fd5b61062689896107ad565b925086516040519080825280602002602001820160405280156106585781602001602082028038833980820191505090505b509150600090505b865181101561078957600183601b898481518110151561067c57fe5b9060200190602002015101888481518110151561069557fe5b9060200190602002015188858151811015156106ad57fe5b90602001906020020151604051600081526020016040526040518085600019166000191681526020018460ff1660ff1681526020018360001916600019168152602001826000191660001916815260200194505050505060206040516020810390808403906000865af1158015610728573d6000803e3d6000fd5b50505060206040510351828281518110151561074057fe5b9060200190602002019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250508080600101915050610660565b61079282610873565b151561079d57600080fd5b6001935050505095945050505050565b60008060606107bc85856104d9565b91506040805190810160405280601c81526020017f19457468657265756d205369676e6564204d6573736167653a0a333200000000815250905080826040518083805190602001908083835b60208310151561082d5780518252602082019150602081019050602083039250610808565b6001836020036101000a03801982511681845116808217855250505050505090500182600019166000191681526020019250505060405180910390209250505092915050565b60008060006001805490508451111561088b57600080fd5b600091505b83518210156109955760008085848151811015156108aa57fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16151561090757600080fd5b600090505b8181101561098857838181518110151561092257fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff16848381518110151561095057fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff16141561097b57600080fd5b808060010191505061090c565b8180600101925050610890565b6001925050509190505600a165627a7a72305820cb38384cf3bed927396f7963c78fe7df622577184e16d3b548dda202b6792e590029',
        abi: [
            {
                "constant": true,
                "inputs": [],
                "name": "getRequired",
                "outputs": [
                    {
                        "name": "",
                        "type": "uint256"
                    }
                ],
                "payable": false,
                "stateMutability": "view",
                "type": "function"
            },
            {
                "constant": false,
                "inputs": [
                    {
                        "name": "destination",
                        "type": "address"
                    },
                    {
                        "name": "value",
                        "type": "uint256"
                    },
                    {
                        "name": "vs",
                        "type": "uint8[]"
                    },
                    {
                        "name": "rs",
                        "type": "bytes32[]"
                    },
                    {
                        "name": "ss",
                        "type": "bytes32[]"
                    }
                ],
                "name": "spend",
                "outputs": [],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [],
                "name": "getOwners",
                "outputs": [
                    {
                        "name": "",
                        "type": "address[]"
                    }
                ],
                "payable": false,
                "stateMutability": "view",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [],
                "name": "getSpendNonce",
                "outputs": [
                    {
                        "name": "",
                        "type": "uint256"
                    }
                ],
                "payable": false,
                "stateMutability": "view",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [
                    {
                        "name": "destination",
                        "type": "address"
                    },
                    {
                        "name": "value",
                        "type": "uint256"
                    }
                ],
                "name": "generateMessageToSign",
                "outputs": [
                    {
                        "name": "",
                        "type": "bytes32"
                    }
                ],
                "payable": false,
                "stateMutability": "view",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [],
                "name": "MAX_OWNER_COUNT",
                "outputs": [
                    {
                        "name": "",
                        "type": "uint256"
                    }
                ],
                "payable": false,
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "name": "_owners",
                        "type": "address[]"
                    },
                    {
                        "name": "_required",
                        "type": "uint256"
                    }
                ],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "constructor"
            },
            {
                "payable": true,
                "stateMutability": "payable",
                "type": "fallback"
            },
            {
                "anonymous": false,
                "inputs": [
                    {
                        "indexed": false,
                        "name": "new_balance",
                        "type": "uint256"
                    }
                ],
                "name": "Funded",
                "type": "event"
            },
            {
                "anonymous": false,
                "inputs": [
                    {
                        "indexed": false,
                        "name": "to",
                        "type": "address"
                    },
                    {
                        "indexed": false,
                        "name": "transfer",
                        "type": "uint256"
                    }
                ],
                "name": "Spent",
                "type": "event"
            }
        ],
    };

    let contract = web3.eth.contract(contractData.abi);

    return `0x${contract.new.getData.apply(null, args.concat({ data: contractData.bytecode }))}`;
};

module.exports = {
    createTokenData: createTokenData,
    mapEthTransaction: mapEthTransaction,
    getTxData: getTxData,
    generateEosKeyPair: generateEosKeyPair,
    getDeployContractTxData: getDeployContractTxData
};