## Coverage report of contract!!!

| File                                  | % Lines         | % Statements    | % Branches    | % Funcs       |
|---------------------------------------|----------------|----------------|---------------|---------------|
| script/Deploy.s.sol                   | 80.00% (8/10)  | 81.82% (9/11)  | 100.00% (0/0) | 50.00% (1/2)  |
| src/MerkleAirdrop.sol                 | 67.65% (23/34) | 74.07% (20/27) | 0.00% (0/5)   | 75.00% (6/8)  |
| src/Token.sol                         | 100.00% (2/2)  | 100.00% (1/1)  | 100.00% (0/0) | 100.00% (1/1) |
| **Total**                             | **30.28% (33/109)** | **25.64% (30/117)** | **0.00% (0/10)** | **42.11% (8/19)** |



## Summary of Complete protocol/application



1. **User Signs the Claim:**
   - Users signs claim message using *private-key* 
   - `v, r, s` components are generated using ECDSA
   - *Signature Security*

2. **Gas Payer Submits the Claim**:
   - The gas payer (third party) submits the airdrop claim `on behalf of the user.` 
   - *Gasless Claims*

3. **Smart Contract Verifies the Claim**:
   - Contract uses `tryRecover()` function to recover the signer’s address from the signature.
   - *Contract verifies with actual signer's address*
   - *On-Chain Verification*

4. **Merkle Proof Validation**:
   - Here, implemented merkle tree and merkle proofs to `validate whether user is eligible for claim `
   -  *Efficient Validation*

5. **Airdrop is Processed**:
   - If all claim is passed, contract then `transfers the claim-amount` to user!!! 




## Merkle Trees and Merkle Proofs

- They provide a reliable method for verifying the presence of data within a larger dataset
- Each piece of data is hashed, and these hashes are organized in a hierarchical data structure called Merkle tree
- By comparing hashes along a path from the data to the root, one can verify the authenticity of specific data.
- Without Merkle proofs, the verification would require downloading the entire blockchain because blockchain architectures store all transaction data in linear order, and to verify a single transaction, one would need to validate every block and transaction that came before it.
- Hash functions are used in Merkle Proofs to hash all the transactions in a data block and further create a Merkle tree by hashing all pairs of nodes until the top of the tree is reached. The concept of Merkle trees and proofs is based on Hashing.



### Merkle Tress

**Note: We can use merkle trees and proofs to efficiently store the `1000+ addresses on-chain` to verify and use for any verification tasks.**

- It is a data structure similar to binary tree
- It acts as a summary of all the transactions in a block, `enabling fast and secure verification` of data across larger datasets.
- We can use merkle tree to store data in hash form to `optimize the searching and security of our application`


**Example for merkle trees**:
1. **Leaf Nodes**:
    - Consider four transactions block or data (T1,T2,T3,T4)
    - Their hash form will be (H1,H2,H3,H4)

2. **Intermediate Nodes**:
    - This nodes will be hash of its children nodes
    - `H12 -> hash of H1 and H2`
    - `H34 -> hash of H3 and H4`

3. **Root Nodes**:
    - This contains the hash of its intermediate nodes
    - `H1234 -> hash of H12 and H34`



- Each pair has a computed hash that is stored directly in the parent node
- These nodes are then grouped into pairs, and their hash is stored on the next level up. 
- This process continues until reaching the top of the Merkle tree (root node)




### Merkle Proofs

- It is a method to prove that a specific piece of data is a `part of Merkle tree`, without needing access to the entire Merkle tree.
- For verification we need the hash of `sibling nodes`!!!

- To verify that data is indeed present in tree, we need the `hash of sibling nodes` and `hash of actual data`


**Example to verify data presence:**
1. **Get hash of data**:
    - Let's check for T2 presence
    - Get hash of T2->H2
    - Need hash of sibling node (H1)

2. **Check hashing with H12**:
   - Hash both leaf node (H1 and H2) to get H12
   - We will require hash of H34

3. **Check with intermediate sibling node**:
    - Hash both H12 and H34
    - Compare the above hash(H1234) with provided hash of root node.
    - If correct -> data is Present in tree



*A smart contract can store only the Merkle root on-chain, saving more gas than storing every address on an airdrop. The Merkle tree generates a Merkle proof, which can be verified to prove eligibility. This proof authenticates a specific wallet address included in the list of eligible wallets by comparing it to the Merkle root.*





## Signature Verification

**Signatures provide a means for authentication in blockchain technology, allowing operations, such as sending transactions, to be verified that they have originated from the intended signer.**
- In blockchain applications, `signature verification` ensures that a message, transaction, or data was signed by the rightful owner of a private key.
- ` Signature verification` is the process of checking whether a `cryptographic signature was created by the legitimate owner` of an Ethereum address

- It also confirms:
  - **The message was signed using the correct private key.**
  - **The message was not tampered with after signing.**




### Why we need Signature verification?


**Ethereum uses Elliptic Curve Digital Signature Algorithm (ECDSA) to generate signatures.**
- We can use `Signature Verification` in our application to provide on-chain authenticity and security!!!

**Some Application of Signature Verification:**

1. **Ensuring Authenticity & Identity**:
    - Only the private key owner can generate a valid signature.
    - This allows off-chain signing and on-chain verification, reducing gas costs
    - `Example: An admin signs an airdrop claim request, ensuring only eligible users can claim tokens.`

2. **Gasless Transactions**:
    - Users sign messages off-chain instead of sending transactions.
    - A relayer (gasPayer) submits the transaction on-chain, paying gas fees.
    - `Use case: Airdrops, voting, and gasless DeFi interactions.`

3. **Preventing Replay Attacks**:
    - Signature verification ensures no one else can fake a transaction.
    - Unique nonces prevent replaying old valid signatures.
    - `Example: Preventing users from claiming an airdrop multiple times.`

4. **Smart Contract Security**:
    - Ensures only authorized users interact with sensitive contract functions.
    - Can replace msg.sender checks for access control.
    - `Example: Permit functions in ERC20 (EIP-2612) allow token approvals via signatures`




### Signature Standards

**When signing transactions, there needed to be an easier way to read transaction data!!!**


- `Signature standards` meant that transactions could be `displayed in a readable way` during transaction!!!
- `Simple SIgnature` is available easily on solidity but data is displayed in hash and bytes format!!!
  
- `EIP-191 and EIP-712` allow us to display TNX data in `structural and readable way` 


1. **SImple SIgnature**:
    - In this, we will create a function that will take data(any msg.) and signatures component(r,s,v).
    - Retrives the signer address
    - And, lastly compares with original signer address.
    - `ecrecover` is percompile function -> retrieves the signer address!!!

    ```solidity
    <!-- This Will Retrive the signer addresss -->
    function getSignerSimple(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public pure returns (address) {
        // if message is string, use keccak256(abi.encodePacked(string))!!!
        bytes32 hashedMessage = bytes32(message);
        // retrieve the signer
        address signer = ecrecover(hashedMessage, _v, _r, _s);
        return signer;
    }   
    <!-- This will compare the signer addresss with actual signer addresss -->
    function verifySignerSimple(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer
    )
	public pure returns (bool){
        address actualSigner = getSignerSimple(message, _v, _r, _s);
        require(signer == actualSigner);
        return true;
    }
    ```



2. **EIP-191 (Standardizing Signatures)**:
    - EIP-191 defines how messages should be signed off-chain and verified on-chain.
    - *Prevents signature replay attacks by defining a structured message format.* 
    - `EIP-191 Format:` -> 0x19 <byte version> <Validator address> <Data/Msg>
    
    - `0x19`-> prefix that signifies data is signature
    - <byte version>: The version of “signed data” is used.
        - `0x00`: Data with the intended validator
        - `0x01`: Structures data - most often used in production apps
        - `0x02`: personal_sign messages
    - <data to sign>: The message intended to be signed.

    ```solidity
    <!-- Function shows how to use EIP-191 Format and retrieves signature -->
    function getSigner191(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public view returns (address) {
        
        bytes1 prefix = bytes1(0x19);
        bytes1 eip191Version = bytes1(0);
        address indendedValidatorAddress = address(this);
        bytes32 applicationSpecificData = bytes32(message);

        // 0x19 <byte version> <Validator address> <Hash Data>
        bytes32 hashedMessage =
            keccak256(abi.encodePacked(prefix, eip191Version, indendedValidatorAddress, applicationSpecificData));

        address signer = ecrecover(hashedMessage, _v, _r, _s);
        return signer;
    }
    <!-- Function will compare the actual signer -->
    function verifySigner191(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer)
	public view returns (bool){
        address actualSigner = getSigner191(message, _v, _r, _s);
        require(signer == actualSigner);
        return true;
    }
    ```

    - **Application**: 
        - MetaMask `signMessage()` follows EIP-191 when signing messages.
        - Verifying off-chain messages in smart contracts (e.g.,` proving identity in Web3 apps`).




3. **EIP712: Making Signatures Readable**:
    - If data gets complicated, we will use EIP-712!!!    
    - EIP-712 introduced standardized data: typed structured data hashing and signing.
    - `EIP-712 Format:` -> 0x19 0x01 <domainSeparator> <hashStruct(message)>
    - EIP-712 prevents replay-attacks.
    

    ```solidity
    <!-- Create Message Typehash -->
    struct MerkleAirdropDomain {
        address account;
        uint256 amount;
    }
    bytes32 constant MESSAGE_TYPEHASH = keccak256("MerkleAirdropDomain(address account,uint256 amount)");
    <!-- Get Domain Separator -->
    function getMessageHash(address account,uint256 amount) public pure returns(bytes32) {
        return (
            keccak256(
                abi.encode(
                    MESSAGE_TYPEHASH,
                    MerkleAirdropDomain({account:account,amount:amount})
                )
            )
        );
    }
    <!-- Function will sign the TNX using EIP-712 format -->
    function getSignerEIP712(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public view returns (address) {
        bytes1 prefix = bytes1(0x19);
        // EIP-712 is version 1 of EIP-191
        bytes1 eip712Version = bytes1(0x01);
        // Domain Separator / hash the message struct
        bytes32 hashStructOfDomainSeparator = getMessageHash(account,amount);
        // And finally, combine them all
        bytes32 digest = keccak256(abi.encodePacked(prefix, eip712Version, hashStructOfDomainSeparator, hashedMessage));
        // returns the signer address
        return ecrecover(digest, _v, _r, _s);
    }
    <!-- finallly compare the actual signer addresss -->
    function verifySigner712(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer)
    public view returns (bool){
        address actualSigner = getSignerEIP712(message, _v, _r, _s);
        require(signer == actualSigner);
        return true;
    }
    ``` 

    - **Application**:
        - Gasless transactions
        - Permit function (EIP-2612) → Allows users to sign approvals without sending transactions.
        - Secure off-chain authentication (Sign-In With Ethereum).




4. **Replay Attacks**:
    - Same TNX can be sent more than once using same signature
    - The extra data in the structure of EIP-712 ensures replay resistance.

    - To prevent replay attacks we can consider following points:
        - Have every signature have a `unique nonce` that is validated
        - Restrict the s value to a single half
        - Include a `chain ID` to prevent cross-chain replay attacks 



- **EIP-191: standardizes what signed data should look like.**
- **EIP-712: standardizes the format of the version-specific data and the data to sign.**






## ECDSA ALGORITHM


- The `ECDSA` is based on `Elliptic Curve Cryptography (ECC)`
- *Signatures provide a means for authentication in blockchain technology, allowing operations, such as sending transactions, to be verified that they have originated from the intended signer.*

- **In Ethereum, ECDSA is used for the following:**
    - Key generation
    - Signing messages
    - Signature verification


- **The Elliptic Curve Digital Signature Algorithm (ECDSA) is a signature algorithm based on Elliptic Curve Cryptography (ECC).**
- **`secp256k1`**, is the specific curve used in ECDSA in Ethereum


### Digital Signature Creation Process

- Using ECDSA algorithm, hash the msg. and then combine hash with private keys called as `Signing a Message`
- After Signing -> Digital signature is created
- Each distinct msg. generates unique hash results in `unique signature`



### Signatures components (r,s,v)

- This components can be generated by splitting signatures that is generated during TNX.

1. `r` -> 32-bytes -> A point on curve (secp256k1)
2. `s` -> 32-bytes ->  value that proves the signer knows the private key without revealing it.
3. `v` -> uint8(1-bytes) ->  helps determine the correct public key.



#### Summary

- **Ethereum uses Elliptic Curve Digital Signature Algorithm (ECDSA) to generate signatures.**
- `ECDSA` is an cryptographic algorithm
- used to generate key pairs, creating signatures and verifying signatures.
- Use an elliptic curve `secp256k1`
- Use signatures component for digital signatures `(r,s,v)`
- (r,s,v) refferred from elliptic curve



### TRANSACTION TYPES


1. **Type(0) Legacy Transaction**:

2.**Type(1) 0x01 TNX:**
    - optional access list(EIP-2930)
    - Contains additional access list parameters
    - Addressed contract breakage risks from (EIP-2929)
    - This enables gas saving on cross-contract calls by pre-declaring the allowd contract and storage

3. **Type(2) 0x02:**
    - An EIP-1559
    - Replace gasprice with base fee
    - Required new params


4. **Blob Transaction(EIP-4844):**
    - Scaling solutions for rollups
    - Rollups has adopted this type of transaction to optimized the gas transaction fees



### IMPLEMENT SIGNATURES ON-CHAIN


- To implement the signature verification in our protocols/application, we can try the following method:

```solidity
// This function will contain some logic to claiming airdrop tokens
function claim(
        address account,
        uint256 amount,
        uint8 _v,
	    bytes32 _r,
	    bytes32 _s
    ) external {

        // verify the signature
        if(!_isValidSignature(account,getMessageHash(account, amount),_r,_s,_v)){
            revert MerkleAirdrop_InvalidSignature();
        }

        i_token.safeTransfer(account, amount);
}
// We will follow the EIP-712 format
struct MerkleAirdropDomain {
    address account;
    uint256 amount;
}
bytes32 constant MESSAGE_TYPEHASH = keccak256("MerkleAirdropDomain(address account,uint256 amount)");
// Get Domain Separator
function getMessageHash(address account,uint256 amount) public pure returns(bytes32) {
        return (
            keccak256(
                abi.encode(
                    MESSAGE_TYPEHASH,
                    MerkleAirdropDomain({account:account,amount:amount})
            )
        )
    );
}
// Check for valid signature
function _isValidSignature(address signer,bytes32 digest,bytes32 r,bytes32 s, uint8 v) internal pure returns(bool){
    (address actualSigner, ,) = ECDSA.tryRecover(digest, v,r,s);
    return (actualSigner == signer);
}


// Simple test to verify the signature
function getSigComponent(uint256 privateKey,address account,uint256 amount) public view returns(uint8 v, bytes32 r, bytes32 s){
    bytes32 digest = merkleAirdrop.getMessageHash(account, amount);
    (v,r,s) = vm.sign(privateKey, digest);
}
function test_CheckUserCanClaim() public {
    uint256 userInitialBalance = token.balanceOf(user);
    console.log("userInitialBalance : ",userInitialBalance);

    // get the signature
    (v, r, s) = getSigComponent(userPrivateKey, user, AMOUNT);

    // gasPayer claims the airdrop for the user
    vm.startPrank(gasPayer);
    merkleAirdrop.claim(user, AMOUNT,MERKLE_PROOF,v,r,s);
    
    // merkleAirdrop.claimWithoutSig(user, AMOUNT, MERKLE_PROOF);
    vm.stopPrank();
    uint256 userEndingBalance = token.balanceOf(user);
    console.log("userEndingBalance : ",userEndingBalance);
    assert(userEndingBalance == AMOUNT + userInitialBalance);
}
```




## Generating merkle tree and merkle proofs using solidity script and library

- We can generate merkle tree using solidity

```solidity
//////////////////////
// GenerateInput.s.sol //
//////////////////////

import {Script} from "lib/forge-std/src/Script.sol";
import {stdJson} from "lib/forge-std/src/StdJson.sol";
import {console} from "lib/forge-std/src/console.sol";
contract GenerateInput is Script {
    uint256 private constant AMOUNT = 25 * 1e18; // 25000000000000000000
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



//////////////////////
// MakeMerkle.s.sol //
//////////////////////

import {Script} from "lib/forge-std/src/Script.sol";
import {stdJson} from "lib/forge-std/src/StdJson.sol";
import {console} from "lib/forge-std/src/console.sol";
import {Merkle} from "lib/murky/src/Merkle.sol";
import {ScriptHelper} from "lib/murky/script/common/ScriptHelper.sol";
contract MakeMerkle is Script, ScriptHelper {
    using stdJson for string; // enables us to use the json cheatcodes for strings

    Merkle private m = new Merkle(); // instance of the merkle contract from Murky to do shit

    string private inputPath = "/script/target/input.json";
    string private outputPath = "/script/target/output.json";

    // Get the input file elements
    string private elements = vm.readFile(string.concat(vm.projectRoot(), inputPath));
    // gets the merkle tree leaf types from json using forge standard lib cheatcode 
    string[] private types = elements.readStringArray(".types");
    // get the number of leaf nodes
    uint256 private count = elements.readUint(".count");

    // make three arrays the same size as the number of leaf nodes
    bytes32[] private leafs = new bytes32[](count);

    string[] private inputs = new string[](count);
    string[] private outputs = new string[](count);

    string private output;

    /// @dev Returns the JSON path of the input file
    // output file output ".values.some-address.some-amount"
    function getValuesByIndex(uint256 i, uint256 j) internal pure returns (string memory) {
        return string.concat(".values.", vm.toString(i), ".", vm.toString(j));
    } 

    /// @dev Generate the JSON entries for the output file
    function generateJsonEntries(string memory _inputs, string memory _proof, string memory _root, string memory _leaf)
        internal
        pure
        returns (string memory)
    {
        string memory result = string.concat(
            "{",
            "\"inputs\":",
            _inputs,
            ",",
            "\"proof\":",
            _proof,
            ",",
            "\"root\":\"",
            _root,
            "\",",
            "\"leaf\":\"",
            _leaf,
            "\"",
            "}"
        );

        return result;
    }

    /// @dev Read the input file and generate the Merkle proof, then write the output file
    function run() public {
        console.log("Generating Merkle Proof for %s", inputPath);

        for (uint256 i = 0; i < count; ++i) {
            string[] memory input = new string[](types.length); // stringified data (address and string both as strings)
            bytes32[] memory data = new bytes32[](types.length); // actual data as a bytes32

            for (uint256 j = 0; j < types.length; ++j) {
                if (compareStrings(types[j], "address")) {
                    address value = elements.readAddress(getValuesByIndex(i, j));
                    // you can't immediately cast straight to 32 bytes as an address is 20 bytes so first cast to uint160 (20 bytes) cast up to uint256 which is 32 bytes and finally to bytes32
                    data[j] = bytes32(uint256(uint160(value))); 
                    input[j] = vm.toString(value);
                } else if (compareStrings(types[j], "uint")) {
                    uint256 value = vm.parseUint(elements.readString(getValuesByIndex(i, j)));
                    data[j] = bytes32(value);
                    input[j] = vm.toString(value);
                }
            }
            // Create the hash for the merkle tree leaf node
            // abi encode the data array (each element is a bytes32 representation for the address and the amount)
            // Helper from Murky (ltrim64) Returns the bytes with the first 64 bytes removed 
            // ltrim64 removes the offset and length from the encoded bytes. There is an offset because the array
            // is declared in memory
            // hash the encoded address and amount
            // bytes.concat turns from bytes32 to bytes
            // hash again because preimage attack
            leafs[i] = keccak256(bytes.concat(keccak256(ltrim64(abi.encode(data)))));
            // Converts a string array into a JSON array string.
            // store the corresponding values/inputs for each leaf node
            inputs[i] = stringArrayToString(input);
        }

        for (uint256 i = 0; i < count; ++i) {
            // get proof gets the nodes needed for the proof & stringify (from helper lib)
            string memory proof = bytes32ArrayToString(m.getProof(leafs, i));
            // get the root hash and stringify
            string memory root = vm.toString(m.getRoot(leafs));
            // get the specific leaf working on
            string memory leaf = vm.toString(leafs[i]);
            // get the singified input (address, amount)
            string memory input = inputs[i];

            // generate the Json output file (tree dump)
            outputs[i] = generateJsonEntries(input, proof, root, leaf);
        }

        // stringify the array of strings to a single string
        output = stringArrayToArrayString(outputs);

        // write to the output file the stringified output json (tree dump)
        vm.writeFile(string.concat(vm.projectRoot(), outputPath), output);

        console.log("DONE: The output is found at %s", outputPath);
    }
}
```



## Generate merkle Trees and Proofs using javascript library

- Generate merkle trees and proofs using javascript library

```js
//////////////////////
// createMerkleProof.js //
//////////////////////
import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import fs from "fs";

// (1)
const tree = StandardMerkleTree.load(JSON.parse(fs.readFileSync("tree.json", "utf8")));

// (2) on frontend we can enable the gas payer to access the proofs by passing the address details
for (const [i, v] of tree.entries()) {
  if (v[0] === '0x6CA6d1e2D5347Bfab1d91e883F1915560e09129D') {
    // (3)
    const proof = tree.getProof(i);
    console.log('Value:', v);
    console.log('Proof:', proof);
    // writing proof for address(account) in proof.json
    fs.writeFileSync("Target/proof.json", JSON.stringify(proof));
  }
}

//////////////////////
// createMerkleTree.js //
//////////////////////
import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import fs from "fs";


const allowlist = [
    ["0x6CA6d1e2D5347Bfab1d91e883F1915560e09129D","25000000000000000000"],
    ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","25000000000000000000"],
    ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8","25000000000000000000"],
    ["0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC","25000000000000000000"],
    ["0x90F79bf6EB2c4f870365E785982E1f101E93b906","25000000000000000000"]
];


const tree = StandardMerkleTree.of(allowlist, ["address", "uint256"]);

// returns the root of merkle tree
console.log('Merkle Root:', tree.root);


// write the complete merkle tree in tree.json
fs.writeFileSync("Target/tree.json", JSON.stringify(tree.dump()));
```





### Sources

1. **Merkle trees and Proofs**:
    - https://medium.com/@swastika0015/merkle-proofs-explained-208a72971a50

2. **EIP-712 and EIP-191**:
    - https://www.cyfrin.io/blog/understanding-ethereum-signature-standards-eip-191-eip-712

3. **ECDSA signature algorithm**:
    - https://www.cyfrin.io/blog/elliptic-curve-digital-signature-algorithm-and-signatures
    - https://fitsaleem.medium.com/ethereums-elliptic-curve-digital-signature-algorithm-ecdsa-88e1659f4879

4. **Openzepplein create merkle tree js library**:
   - https://github.com/OpenZeppelin/merkle-tree 
   - https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/structs/BitMaps.sol