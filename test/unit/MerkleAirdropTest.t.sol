// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test,console,Vm} from "lib/forge-std/src/Test.sol";
import {Token} from "src/Token.sol";
import {MerkleAirdrop} from "src/MerkleAirdrop.sol";
import {IERC20 } from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ZkSyncChainChecker} from "lib/foundry-devops/src/ZkSyncChainChecker.sol";
import {DeployTokenAndAirdropContract} from "script/Deploy.s.sol";

contract MerkleAirdropTest is Test,ZkSyncChainChecker{
    Token public token;
    MerkleAirdrop public merkleAirdrop;

    bytes32 proofOne = 0xe69d442873e63995f17631f1a33e7109f709581ec3a6ee8b5d4f82efac1fbbec;
    bytes32 proofTwo = 0x057f7ddc2e145c80e02849d93e3faad5d8b4208372dee65c212e88f57fe0b62d; 
    bytes32[] public MERKLE_PROOF = [proofOne,proofTwo];
    bytes32 public merkleRoot = 0xab33a8088ce135ce1d06a3f89567941e5d8d12fac70322b9c27a5f96ce546fa6;
    address user;
    uint256 userPrivateKey;
    uint256 AMOUNT = 25 * 1e18; // 25.000000
    uint256 AMOUNT_TO_MINT = AMOUNT * 4;

    function setUp() public {
        if(!isZkSyncChain()){
            DeployTokenAndAirdropContract deployContract = new DeployTokenAndAirdropContract();
            (token,merkleAirdrop) = deployContract.setUp();
        }else{
            token = new Token();
            merkleAirdrop = new MerkleAirdrop(merkleRoot,IERC20(token));
            token.mint(token.owner(), AMOUNT_TO_MINT);
            token.transfer(address(merkleAirdrop),AMOUNT_TO_MINT);
        }
        

        (user,userPrivateKey) = makeAddrAndKey("user");
    }

    function test_CheckUserCanClaim() public {
        uint256 userInitialBalance = token.balanceOf(user);
        console.log(userInitialBalance);

        vm.prank(user);
        merkleAirdrop.claim(user, AMOUNT,MERKLE_PROOF);

        uint256 userEndingBalance = token.balanceOf(user);
        console.log(userEndingBalance);
        
    }

    function test_RevertsIf_UserIsNotClaimer() public {
        
    }
}