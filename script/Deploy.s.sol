// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "lib/forge-std/src/Script.sol";
import {Token} from "src/Token.sol";
import {MerkleAirdrop} from "src/MerkleAirdrop.sol";
import {IERC20 } from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";

/**
 * @title DeployTokenAndAirdropContract deploy script contract
 * @author anurag shingare
 * @notice An deploy script to deploy contract on any layer and roll-ups blockchain network
 * @notice Here, during deploying the contract we need to provide the merkle root 
 */

contract DeployTokenAndAirdropContract is Script{

    bytes32 public merkleRoot = 0x74ddccb6e201771dc8ddcc9759f73a3bb6851b67f57500b2f7fc2323c03344ba;
    uint256 AMOUNT_TO_CLAIM = 25 * 1e18;
    uint256 AMOUNT_TO_MINT = 4 * (AMOUNT_TO_CLAIM); 

    function setUp() public returns(Token,MerkleAirdrop) {
        vm.startBroadcast();
        Token token = new Token();
        MerkleAirdrop merkleAirdrop = new MerkleAirdrop(merkleRoot,IERC20(token));

        token.mint(token.owner(), AMOUNT_TO_MINT);
        IERC20(token).transfer(address(merkleAirdrop), AMOUNT_TO_MINT);
        vm.stopBroadcast();

        return (token,merkleAirdrop);
    }

    function run() public returns(Token,MerkleAirdrop) {
        return setUp();
    }
}