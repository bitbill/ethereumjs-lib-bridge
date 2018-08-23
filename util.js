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
        bytecode: '6080604052600060035534801561001557600080fd5b506040516108f73803806108f783398101604052805160208201519101805190919060009082600982118061004957508181115b80610052575080155b8061005b575081155b1561006557600080fd5b600092505b845183101561013057600080868581518110151561008457fe5b6020908102909101810151600160a060020a031682528101919091526040016000205460ff16806100d5575084838151811015156100be57fe5b90602001906020020151600160a060020a03166000145b156100df57600080fd5b600160008087868151811015156100f257fe5b602090810291909101810151600160a060020a03168252810191909152604001600020805460ff19169115159190911790556001929092019161006a565b8451610143906001906020880190610154565b505050600291909155506101e09050565b8280548282559060005260206000209081019282156101a9579160200282015b828111156101a95782518254600160a060020a031916600160a060020a03909116178255602090920191600190910190610174565b506101b59291506101b9565b5090565b6101dd91905b808211156101b5578054600160a060020a03191681556001016101bf565b90565b610708806101ef6000396000f30060806040526004361061006c5763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166385b2566a81146100a2578063a0e67e2b1461017d578063c6a2a9f1146101e2578063d0590bad14610209578063d74f8edd1461022d575b604080513031815290517fc4c14883ae9fd8e26d5d59e3485ed29fd126d781d7e498a4ca5c54c8268e49369181900360200190a1005b3480156100ae57600080fd5b50604080516020600460443581810135838102808601850190965280855261017b958335600160a060020a0316956024803596369695606495939492019291829185019084908082843750506040805187358901803560208181028481018201909552818452989b9a998901989297509082019550935083925085019084908082843750506040805187358901803560208181028481018201909552818452989b9a9989019892975090820195509350839250850190849080828437509497506102429650505050505050565b005b34801561018957600080fd5b506101926102f3565b60408051602080825283518183015283519192839290830191858101910280838360005b838110156101ce5781810151838201526020016101b6565b505050509050019250505060405180910390f35b3480156101ee57600080fd5b506101f7610355565b60408051918252519081900360200190f35b34801561021557600080fd5b506101f7600160a060020a036004351660243561035b565b34801561023957600080fd5b506101f76103bd565b303184111561025057600080fd5b61025d85858585856103c2565b151561026857600080fd5b600380546001019055604051600160a060020a0386169085156108fc029086906000818181858888f193505050501580156102a7573d6000803e3d6000fd5b5060408051600160a060020a03871681526020810186905281517fd3eec71143c45f28685b24760ea218d476917aa0ac0392a55e5304cef40bd2b6929181900390910190a15050505050565b6060600180548060200260200160405190810160405280929190818152602001828054801561034b57602002820191906000526020600020905b8154600160a060020a0316815260019091019060200180831161032d575b5050505050905090565b60035490565b600080600160a060020a03841630141561037457600080fd5b5050600354604080519182526c01000000000000000000000000308102602084015260348301849052600160a060020a0385160260548301525190819003606801902092915050565b600981565b60008060606000855187511415156103d957600080fd5b84518651146103e757600080fd5b600154875111156103f757600080fd5b6002548751101561040757600080fd5b610411898961054e565b9250865160405190808252806020026020018201604052801561043e578160200160208202803883390190505b509150600090505b865181101561052b57600183888381518110151561046057fe5b90602001906020020151601b01888481518110151561047b57fe5b90602001906020020151888581518110151561049357fe5b60209081029091018101516040805160008082528185018084529790975260ff9095168582015260608501939093526080840152905160a0808401949293601f19830193908390039091019190865af11580156104f4573d6000803e3d6000fd5b50505060206040510351828281518110151561050c57fe5b600160a060020a03909216602092830290910190910152600101610446565b610534826105fe565b151561053f57600080fd5b50600198975050505050505050565b600080606061055d858561035b565b91506040805190810160405280601c81526020017f19457468657265756d205369676e6564204d6573736167653a0a333200000000815250905080826040518083805190602001908083835b602083106105c85780518252601f1990920191602091820191016105a9565b51815160209384036101000a60001901801990921691161790529201938452506040519283900301909120979650505050505050565b60008060006001805490508451111561061657600080fd5b600091505b83518210156106d257600080858481518110151561063557fe5b6020908102909101810151600160a060020a031682528101919091526040016000205460ff16151561066657600080fd5b5060005b818110156106c757838181518110151561068057fe5b90602001906020020151600160a060020a031684838151811015156106a157fe5b90602001906020020151600160a060020a031614156106bf57600080fd5b60010161066a565b60019091019061061b565b50600193925050505600a165627a7a72305820a29e19b5b2361136f57b4e719f2b25dddfe7dd6e097238273d93cbc18f51f3470029',
        abi: [
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