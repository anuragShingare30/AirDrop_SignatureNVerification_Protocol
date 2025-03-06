// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test,Vm} from "lib/forge-std/src/Test.sol";
import {console} from "lib/forge-std/src/console.sol";
import {Token} from "src/Token.sol";
import {MerkleAirdrop} from "src/MerkleAirdrop.sol";
import {IERC20 } from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ZkSyncChainChecker} from "lib/foundry-devops/src/ZkSyncChainChecker.sol";
import {DeployTokenAndAirdropContract} from "script/Deploy.s.sol";

contract MerkleAirdropTest is Test,ZkSyncChainChecker{
    Token public token;
    MerkleAirdrop public merkleAirdrop;

    bytes32 proofOne = 0x0fd7c981d39bece61f7499702bf59b3114a90e66b51ba2c53abdf7b62986c00a;
    bytes32 proofTwo = 0x71cc24e40153cd652202ed2d5f1da66f139637de876a4de32f1de1caa0dc8d34; 
    bytes32[] public MERKLE_PROOF = [proofOne,proofTwo];
    bytes32 public merkleRoot = 0x74ddccb6e201771dc8ddcc9759f73a3bb6851b67f57500b2f7fc2323c03344ba;
    address user;
    uint256 userPrivateKey;
    address gasPayer;
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
        user = 0x6CA6d1e2D5347Bfab1d91e883F1915560e09129D;
        gasPayer = makeAddr("gasPayer");
    }

    /**
        @notice getSignatureComponents function
        @param privateKey users EOA private key
        @param account user account
        @param amount the amount of token to be claimed
        @notice This function will be called by the user/claimer to generate the signature components which can be used for verification by gas payer!!!  
        @dev This returns the signature compoenets (v,r,s)
     */ 
    function getSigComponent(uint256 privateKey,address account,uint256 amount) public view returns(uint8 v, bytes32 r, bytes32 s){
        bytes32 digest = merkleAirdrop.getMessageHash(account, amount);
        (v,r,s) = vm.sign(privateKey, digest);
    }

    function test_CheckUserCanClaim() public {
        uint256 userInitialBalance = token.balanceOf(user);
        console.log("userInitialBalance : ",userInitialBalance);

        // get the signature
        (uint8 v, bytes32 r, bytes32 s) = getSigComponent(userPrivateKey, user, AMOUNT);

        // gasPayer claims the airdrop for the user
        vm.startPrank(gasPayer);
        merkleAirdrop.claim(user, AMOUNT,MERKLE_PROOF,v,r,s);
        // merkleAirdrop.claimWithoutSig(user, AMOUNT, MERKLE_PROOF);
        vm.stopPrank();

        uint256 userEndingBalance = token.balanceOf(user);
        console.log("userEndingBalance : ",userEndingBalance);
        assert(userEndingBalance == AMOUNT + userInitialBalance);
    }

    function test_CheckUserClaimWithOutSignature() public{
        uint256 userInitialBalance = token.balanceOf(user);
        console.log("userInitialBalance before claiming airdrop : ",userInitialBalance);


        // gasPayer claims the airdrop for the user
        vm.startPrank(gasPayer);
        merkleAirdrop.claimWithoutSig(user, AMOUNT, MERKLE_PROOF);
        vm.stopPrank();

        uint256 userEndingBalance = token.balanceOf(user);
        console.log("userEndingBalance after claiming airdrop : ",userEndingBalance);
        assert(userEndingBalance == AMOUNT + userInitialBalance);
    }

    
}