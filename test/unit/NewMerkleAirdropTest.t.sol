// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test,Vm} from "lib/forge-std/src/Test.sol";
import {console} from "lib/forge-std/src/console.sol";
import {Token} from "src/Token.sol";
import {MerkleAirdrop} from "src/MerkleAirdrop.sol";
import {IERC20 } from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";


contract NewMerkleAirdropTest is Test{
    Token public token;
    MerkleAirdrop public merkleAirdrop;

    address user = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    uint256 AMOUNT_TO_MINT = 4 * (25 * 1e18);
    uint256 CLAIMING_AMOUNT = 25 * 1e18;

    // MERKLE TREE AND PROOF DETAILS
    bytes32 public merkleRoot = 0x44a82a0003fd32bbf9fa7417b707ebe79982b6eddd944227cf2d29de52c2b9f1;


    function setUp() public {
        token = new Token();
        merkleAirdrop = new MerkleAirdrop(merkleRoot,IERC20(token));
        token.mint(token.owner(), AMOUNT_TO_MINT);
        (token).transfer(address(merkleAirdrop), AMOUNT_TO_MINT);
    }
}