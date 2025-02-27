// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "lib/forge-std/src/Script.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";
import {MerkleAirdrop} from "src/MerkleAirdrop.sol";


contract ClaimingAirdrop is Script {

    // state varaibles
    address CLAIMING_ACCOUNT = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    uint256 CLAIMING_AMOUNT = 25 * 1e18;
    bytes32 PROOF_ONE = 0xd1445c931158119b00449ffcac3c947d028c0c359c34a6646d95962b3b55c6ad;
    bytes32 PROOF_TWO = 0x71cc24e40153cd652202ed2d5f1da66f139637de876a4de32f1de1caa0dc8d34;
    bytes32[] merkleProof = [PROOF_ONE,PROOF_TWO];

    function claimAirdrop(address contractAddress) public {
        vm.startBroadcast();
        // MerkleAirdrop(contractAddress).claim(CLAIMING_ACCOUNT, CLAIMING_AMOUNT, merkleProof, _v, _r, _s);
        vm.stopBroadcast();
    }

    function run() public {
         address contractAddress = DevOpsTools.get_most_recent_deployment("MerkleAirdrop", block.chainid);
         claimAirdrop(contractAddress);
    }
}