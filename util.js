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
        bytecode: '608060405234801561001057600080fd5b50604051610ba1380380610ba18339810160409081528151602080840151838501516060860151336000908152600585529586208590556003859055918601805194969095919492019261006792908601906100ab565b50805161007b9060019060208401906100ab565b50506002805460ff90921660ff19909216919091179055505060048054600160a060020a03191633179055610146565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100ec57805160ff1916838001178555610119565b82800160010185558215610119579182015b828111156101195782518255916020019190600101906100fe565b50610125929150610129565b5090565b61014391905b80821115610125576000815560010161012f565b90565b610a4c806101556000396000f3006080604052600436106100da5763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166306fdde0381146100dc578063095ea7b31461016657806318160ddd1461019e57806323b872dd146101c5578063313ce567146101ef5780633bed33ce1461021a57806342966c68146102325780636623fc461461024a57806370a08231146102625780638da5cb5b1461028357806395d89b41146102b4578063a9059cbb146102c9578063cd4217c1146102ed578063d7a78db81461030e578063dd62ed3e14610326575b005b3480156100e857600080fd5b506100f161034d565b6040805160208082528351818301528351919283929083019185019080838360005b8381101561012b578181015183820152602001610113565b50505050905090810190601f1680156101585780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561017257600080fd5b5061018a600160a060020a03600435166024356103db565b604080519115158252519081900360200190f35b3480156101aa57600080fd5b506101b3610417565b60408051918252519081900360200190f35b3480156101d157600080fd5b5061018a600160a060020a036004358116906024351660443561041d565b3480156101fb57600080fd5b506102046105b8565b6040805160ff9092168252519081900360200190f35b34801561022657600080fd5b506100da6004356105c1565b34801561023e57600080fd5b5061018a600435610616565b34801561025657600080fd5b5061018a6004356106b7565b34801561026e57600080fd5b506101b3600160a060020a0360043516610771565b34801561028f57600080fd5b50610298610783565b60408051600160a060020a039092168252519081900360200190f35b3480156102c057600080fd5b506100f1610792565b3480156102d557600080fd5b506100da600160a060020a03600435166024356107ec565b3480156102f957600080fd5b506101b3600160a060020a03600435166108f0565b34801561031a57600080fd5b5061018a600435610902565b34801561033257600080fd5b506101b3600160a060020a03600435811690602435166109bc565b6000805460408051602060026001851615610100026000190190941693909304601f810184900484028201840190925281815292918301828280156103d35780601f106103a8576101008083540402835291602001916103d3565b820191906000526020600020905b8154815290600101906020018083116103b657829003601f168201915b505050505081565b60008082116103e957600080fd5b50336000908152600760209081526040808320600160a060020a039590951683529390529190912055600190565b60035481565b6000600160a060020a038316151561043457600080fd5b6000821161044157600080fd5b600160a060020a03841660009081526005602052604090205482111561046657600080fd5b600160a060020a038316600090815260056020526040902054828101101561048d57600080fd5b600160a060020a03841660009081526007602090815260408083203384529091529020548211156104bd57600080fd5b600160a060020a0384166000908152600560205260409020546104e090836109d9565b600160a060020a03808616600090815260056020526040808220939093559085168152205461050f90836109ed565b600160a060020a03808516600090815260056020908152604080832094909455918716815260078252828120338252909152205461054d90836109d9565b600160a060020a03808616600081815260076020908152604080832033845282529182902094909455805186815290519287169391927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef929181900390910190a35060019392505050565b60025460ff1681565b600454600160a060020a031633146105d857600080fd5b600454604051600160a060020a039091169082156108fc029083906000818181858888f19350505050158015610612573d6000803e3d6000fd5b5050565b3360009081526005602052604081205482111561063257600080fd5b6000821161063f57600080fd5b3360009081526005602052604090205461065990836109d9565b3360009081526005602052604090205560035461067690836109d9565b60035560408051838152905133917fcc16f5dbb4873280815c1ee09dbd06736cffcc184412cf7a71a0fdb75d397ca5919081900360200190a2506001919050565b336000908152600660205260408120548211156106d357600080fd5b600082116106e057600080fd5b336000908152600660205260409020546106fa90836109d9565b3360009081526006602090815260408083209390935560059052205461072090836109ed565b33600081815260056020908152604091829020939093558051858152905191927f2cfce4af01bcb9d6cf6c84ee1b7c491100b8695368264146a94d71e10a63083f92918290030190a2506001919050565b60056020526000908152604090205481565b600454600160a060020a031681565b60018054604080516020600284861615610100026000190190941693909304601f810184900484028201840190925281815292918301828280156103d35780601f106103a8576101008083540402835291602001916103d3565b600160a060020a038216151561080157600080fd5b6000811161080e57600080fd5b3360009081526005602052604090205481111561082a57600080fd5b600160a060020a038216600090815260056020526040902054818101101561085157600080fd5b3360009081526005602052604090205461086b90826109d9565b3360009081526005602052604080822092909255600160a060020a0384168152205461089790826109ed565b600160a060020a0383166000818152600560209081526040918290209390935580518481529051919233927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a35050565b60066020526000908152604090205481565b3360009081526005602052604081205482111561091e57600080fd5b6000821161092b57600080fd5b3360009081526005602052604090205461094590836109d9565b3360009081526005602090815260408083209390935560069052205461096b90836109ed565b33600081815260066020908152604091829020939093558051858152905191927ff97a274face0b5517365ad396b1fdba6f68bd3135ef603e44272adba3af5a1e092918290030190a2506001919050565b600760209081526000928352604080842090915290825290205481565b60006109e783831115610a11565b50900390565b6000828201610a0a848210801590610a055750838210155b610a11565b9392505050565b801515610a1d57600080fd5b505600a165627a7a7230582033806bfa9700ccaa66896fb5373e432f587043e8e1731b63e70f29b16400295b0029',
        abi: [
            {
                "constant": true,
                "inputs": [],
                "name": "name",
                "outputs": [
                    {
                        "name": "",
                        "type": "string"
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
                        "name": "_spender",
                        "type": "address"
                    },
                    {
                        "name": "_value",
                        "type": "uint256"
                    }
                ],
                "name": "approve",
                "outputs": [
                    {
                        "name": "success",
                        "type": "bool"
                    }
                ],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [],
                "name": "totalSupply",
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
                        "name": "_from",
                        "type": "address"
                    },
                    {
                        "name": "_to",
                        "type": "address"
                    },
                    {
                        "name": "_value",
                        "type": "uint256"
                    }
                ],
                "name": "transferFrom",
                "outputs": [
                    {
                        "name": "success",
                        "type": "bool"
                    }
                ],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [],
                "name": "decimals",
                "outputs": [
                    {
                        "name": "",
                        "type": "uint8"
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
                        "name": "amount",
                        "type": "uint256"
                    }
                ],
                "name": "withdrawEther",
                "outputs": [],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "constant": false,
                "inputs": [
                    {
                        "name": "_value",
                        "type": "uint256"
                    }
                ],
                "name": "burn",
                "outputs": [
                    {
                        "name": "success",
                        "type": "bool"
                    }
                ],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "constant": false,
                "inputs": [
                    {
                        "name": "_value",
                        "type": "uint256"
                    }
                ],
                "name": "unfreeze",
                "outputs": [
                    {
                        "name": "success",
                        "type": "bool"
                    }
                ],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [
                    {
                        "name": "",
                        "type": "address"
                    }
                ],
                "name": "balanceOf",
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
                "inputs": [],
                "name": "owner",
                "outputs": [
                    {
                        "name": "",
                        "type": "address"
                    }
                ],
                "payable": false,
                "stateMutability": "view",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [],
                "name": "symbol",
                "outputs": [
                    {
                        "name": "",
                        "type": "string"
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
                        "name": "_to",
                        "type": "address"
                    },
                    {
                        "name": "_value",
                        "type": "uint256"
                    }
                ],
                "name": "transfer",
                "outputs": [],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [
                    {
                        "name": "",
                        "type": "address"
                    }
                ],
                "name": "freezeOf",
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
                        "name": "_value",
                        "type": "uint256"
                    }
                ],
                "name": "freeze",
                "outputs": [
                    {
                        "name": "success",
                        "type": "bool"
                    }
                ],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "constant": true,
                "inputs": [
                    {
                        "name": "",
                        "type": "address"
                    },
                    {
                        "name": "",
                        "type": "address"
                    }
                ],
                "name": "allowance",
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
                        "name": "initialSupply",
                        "type": "uint256"
                    },
                    {
                        "name": "tokenName",
                        "type": "string"
                    },
                    {
                        "name": "decimalUnits",
                        "type": "uint8"
                    },
                    {
                        "name": "tokenSymbol",
                        "type": "string"
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
                        "indexed": true,
                        "name": "from",
                        "type": "address"
                    },
                    {
                        "indexed": true,
                        "name": "to",
                        "type": "address"
                    },
                    {
                        "indexed": false,
                        "name": "value",
                        "type": "uint256"
                    }
                ],
                "name": "Transfer",
                "type": "event"
            },
            {
                "anonymous": false,
                "inputs": [
                    {
                        "indexed": true,
                        "name": "from",
                        "type": "address"
                    },
                    {
                        "indexed": false,
                        "name": "value",
                        "type": "uint256"
                    }
                ],
                "name": "Burn",
                "type": "event"
            },
            {
                "anonymous": false,
                "inputs": [
                    {
                        "indexed": true,
                        "name": "from",
                        "type": "address"
                    },
                    {
                        "indexed": false,
                        "name": "value",
                        "type": "uint256"
                    }
                ],
                "name": "Freeze",
                "type": "event"
            },
            {
                "anonymous": false,
                "inputs": [
                    {
                        "indexed": true,
                        "name": "from",
                        "type": "address"
                    },
                    {
                        "indexed": false,
                        "name": "value",
                        "type": "uint256"
                    }
                ],
                "name": "Unfreeze",
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