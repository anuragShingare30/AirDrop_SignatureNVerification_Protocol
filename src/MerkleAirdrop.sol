// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Token} from "src/Token.sol";
import {IERC20, SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {console} from "lib/forge-std/src/console.sol";
import {MerkleProof} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {Merkle} from "lib/murky/src/Merkle.sol";
import {EIP712} from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ScriptHelper} from "lib/murky/script/common/ScriptHelper.sol";

/**
    @title MerkleAirdrop contract
    @author anurag shingare

    @notice Try to implement BitMaps instead of hashmaps to optimize the gas cost
    
    @notice To generate merkle trees,proofs and root:
        a. Run GenerateInput.s.sol -> to generate the input file for accounts and amount
        b. Then run MakeMerkle.s.sol -> to generate leaf node hashes, root hash and sibling node hash!!!
 */

contract MerkleAirdrop is EIP712,ScriptHelper {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // ERRORS
    error MerkleAirdrop_InvalidProof();
    error MerkleAirdrop_InvalidSignature();
    error MerkleAirdrop_AlreadyClaimed();

    // TYPE DECLARATION
    struct MerkleAirdropDomain {
        address account;
        uint256 amount;
    }
    mapping(address account => bool checkClaim) private s_isClaimed;

    // STATE VARIABLES
    // some list of addresses that will claim the airdrops
    bytes32 private immutable i_merkleRoot;
    IERC20 private immutable i_token;
    bytes32 constant MESSAGE_TYPEHASH = keccak256("MerkleAirdropDomain(address account,uint256 amount)");

    // EVENTS
    event MerkleAirdrop_Claimed(address account, uint256 amount);

    // FUNCTIONS
    constructor(bytes32 merkleRoot, IERC20 token)
        EIP712("MerkleAirdrop","1")
     {
        merkleRoot = i_merkleRoot;
        token = i_token;
    }


    /**
        @notice claim function
        
        @notice This function will verify whether the account is present in merkle tree or not
        @notice Using merkle-proof and merkle-root function will verify whether account is present in tree or not 
     */
    function claim(
        address account,
        uint256 amount,
        bytes32[] memory merkleProof,
        uint8 _v,
	    bytes32 _r,
	    bytes32 _s
    ) external {
        if (s_isClaimed[account]) {
            revert MerkleAirdrop_AlreadyClaimed();
        }

        // verify the signature
        if(!_isValidSignature(account,getMessageHash(account, amount),_r,_s,_v)){
            revert MerkleAirdrop_InvalidSignature();
        }

        // hash of account and amount -> leaf node
        // Here, we are hashing twice to avoid hash collision and prevents replay attacks!!!
        // Here we will check for the data presence in our tree!!!
        bytes32 leaf = keccak256(bytes.concat(keccak256(ltrim64(abi.encode(account,amount)))));
        // bytes32 leaf = 0xd1445c931158119b00449ffcac3c947d028c0c359c34a6646d95962b3b55c6ad;
        if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            // 1.
            revert MerkleAirdrop_InvalidProof();
        }

        s_isClaimed[account] = true;

        emit MerkleAirdrop_Claimed(account, amount);

        i_token.safeTransfer(account, amount);
    }


    function claimWithoutSig(
        address account,
        uint256 amount,
        bytes32[] memory merkleProof
    ) external {
        // check whether user already claimed airdrop
        if (s_isClaimed[account]) {
            revert MerkleAirdrop_AlreadyClaimed();
        }

        // verify the presence of account in merkle tree
        _verifyProof(account,amount,merkleProof,i_merkleRoot);

        // mark true for user claim airdrop
        s_isClaimed[account] = true;

        // emit event
        emit MerkleAirdrop_Claimed(account, amount);

        // transfer tokens to user
        i_token.safeTransfer(account, amount);
    }


    // INTERNAL FUNCTIONS
    function _verifyProof(
        address account,
        uint256 amount,
        bytes32[] memory _merkleProof,
        bytes32 _merkleRoot
    ) internal {
        bytes32 leaf = keccak256(bytes.concat(keccak256(ltrim64(abi.encode(account,amount)))));
        require(MerkleProof.verify(_merkleProof, _merkleRoot, leaf),"Invalid Proof!!!");
    }


    function _isValidSignature(address signer,bytes32 digest,bytes32 r,bytes32 s, uint8 v) internal pure returns(bool){
        (address actualSigner, ,) = ECDSA.tryRecover(digest, v,r,s);
        return (actualSigner == signer);
    }

    // EIP-712 format :-
    // 0x19 0x01 <hashStruct(domain separator)> <hashStruct(message)>
    // can be recall as domain separator
    function getMessageHash(address account,uint256 amount) public pure returns(bytes32) {
        return (
            keccak256(
                abi.encode(
                    MESSAGE_TYPEHASH,
                    MerkleAirdropDomain({account:account,amount:amount})
                )
            )
        );
    }
    


    // GETTER FUNCTIONS

    function getMerkleRoot() public view returns (bytes32) {
        return i_merkleRoot;
    }

    function getToken() public view returns (IERC20) {
        return i_token;
    }
}
