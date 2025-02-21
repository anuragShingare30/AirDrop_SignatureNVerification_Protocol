// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test,console,Vm} from "lib/forge-std/src/Test.sol";
import {Token} from "src/Token.sol";
import {MerkleAirdrop} from "src/MerkleAirdrop.sol";

contract MerkleAirdropTest is Test{
    Token token;
    MerkleAirdrop merkleAirdrop;

    function setUp() public {
        
    }
}