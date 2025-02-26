// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "lib/forge-std/src/Script.sol";
import {stdJson} from "lib/forge-std/src/StdJson.sol";
import {console} from "lib/forge-std/src/console.sol";

// Merkle tree input file generator script
// This script file generate the json file for input data in merkle tree
contract GenerateInput is Script {
    uint256 private constant AMOUNT = 25 * 1e18; // 250000000000000000000000
    string[] types = new string[](2);
    uint256 count;
    string[] account = new string[](4);
    string private constant  INPUT_PATH = "/script/target/input.json";

    function run() public {
        types[0] = "address";
        types[1] = "uint";
        account[0] = "0x6CA6d1e2D5347Bfab1d91e883F1915560e09129D";
        account[1] = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
        account[2] = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        account[3] = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
        count = account.length;
        // _createJSON() function will create the input.json file which will contains all addresses and amount as claimers!!!
        string memory input = _createJSON();

        // This cheatcode will write the data in the provided path
        vm.writeFile(string.concat(vm.projectRoot(), INPUT_PATH), input);

        console.log("DONE: The output is found at %s", INPUT_PATH);
        console.log("The project root is: ", vm.projectRoot());
    }

    function _createJSON() internal view returns (string memory) {
        string memory countString = vm.toString(count); // convert count to string
        string memory amountString = vm.toString(AMOUNT); // convert amount to string
        string memory inputJson = string.concat('{ "types": ["address", "uint"], "count":', countString, ',"values": {');
        for (uint256 i = 0; i < account.length; i++) {
            if (i == account.length - 1) {
                inputJson = string.concat(inputJson, '"', vm.toString(i), '"', ': { "0":', '"',account[i],'"',', "1":', '"',amountString,'"', ' }');
            } else {
            inputJson = string.concat(inputJson, '"', vm.toString(i), '"', ': { "0":', '"',account[i],'"',', "1":', '"',amountString,'"', ' },');
            }
        }
        inputJson = string.concat(inputJson, '} }');

        return inputJson;
    }
}