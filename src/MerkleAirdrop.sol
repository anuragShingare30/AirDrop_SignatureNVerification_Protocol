// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Token} from "src/Token.sol";
import {IERC20,SafeERC20 } from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";


contract MerkleAirdrop {
    using SafeERC20 for IERC20;

    // ERRORS
    error MerkleAirdrop_InvalidProof();
    error MerkleAirdrop_AlreadyClaimed();

    // TYPE DECLARATION
    mapping(address account => bool checkClaim) private s_isClaimed;

    // STATE VARIABLES 
    // some list of addresses that will claim the airdrops
    bytes32 private immutable i_merkleRoot;
    IERC20 private immutable i_token;

    // EVENTS
    event MerkleAirdrop_Claimed(address account,uint256 amount);

    // FUNCTIONS
    constructor(
        bytes32 merkleRoot,
        IERC20 token
    ){
        merkleRoot = i_merkleRoot;
        token = i_token;
    }


    function claim(address account,uint256 amount,bytes32[] calldata merkleProof) external{

        if(s_isClaimed[account]){
            revert MerkleAirdrop_AlreadyClaimed();
        }

        // hash of account and amount -> leaf node
        // Here, we are hashing twice to avoid hash collision
        // Checking for presence of data in tree 
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(account,amount))));
        if(!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)){ // 1.
            revert MerkleAirdrop_InvalidProof();
        }

        s_isClaimed[account] = true;

        emit MerkleAirdrop_Claimed(account,amount);

        i_token.safeTransfer(account,amount);
    }

    function getMerkleRoot() public view returns(bytes32) {
        return i_merkleRoot;
    }

    function getToken() public view returns(IERC20){
        return i_token;
    }
}