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