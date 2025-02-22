// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "lib/forge-std/src/Script.sol";
import {Token} from "src/Token.sol";
import {MerkleAirdrop} from "src/MerkleAirdrop.sol";
import {IERC20 } from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";

contract DeployTokenAndAirdropContract is Script{

    bytes32 public merkleRoot = 0xab33a8088ce135ce1d06a3f89567941e5d8d12fac70322b9c27a5f96ce546fa6;
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