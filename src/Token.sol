// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.24;

import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";

/**
 * @title Token Contract
 * @author anurag shingare
 * @title A simple ERC-20 standard contract that contains mint() to mint token and transfer to user
 * @dev We can mint the tokens whenever we want to mint and send the airdrop to users    
 */

contract Token is ERC20, Ownable {
    constructor()
        ERC20("Token", "TKN")
        Ownable(msg.sender)
    {}

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}
