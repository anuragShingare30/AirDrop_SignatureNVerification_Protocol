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
    // bytes32[] merkleProof = new bytes32[](2);
    // merkleProof[0] = 0x9e9863c6fa5d32f9116da49891a1123e03ff838a2a71873fba03c27830e5d102;
    // merkleProof[1] = 0xd78f1fbba3939b30a753f4009f35969e1b41b86430bc94cf5ee3a15dd12b6d1f;


    function setUp() public {
        token = new Token();
        merkleAirdrop = new MerkleAirdrop(merkleRoot,IERC20(token));
        token.mint(token.owner(), AMOUNT_TO_MINT);
        (token).transfer(address(merkleAirdrop), AMOUNT_TO_MINT);
    }


    function test_claimAirdropWithOutSignature() public {
        bytes32[] memory merkleProof = new bytes32[](2);
    merkleProof[0] = 0x9e9863c6fa5d32f9116da49891a1123e03ff838a2a71873fba03c27830e5d102;
    merkleProof[1] = 0xd78f1fbba3939b30a753f4009f35969e1b41b86430bc94cf5ee3a15dd12b6d1f;
        uint256 userInitialBalance = IERC20(token).balanceOf(user);
        console.log(userInitialBalance);
        assert(userInitialBalance == 0);

        // possible code breaking here:
        vm.startPrank(user);
        MerkleAirdrop(merkleAirdrop).claimWithoutSig(user, CLAIMING_AMOUNT, merkleProof);
        vm.stopPrank();


        uint256 userEndingBalance = IERC20(token).balanceOf(user);
        console.log(userEndingBalance);
        assert(userEndingBalance == userInitialBalance+CLAIMING_AMOUNT);
    }
}