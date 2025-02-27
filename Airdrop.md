### Merkle Trees and Merkle Proofs

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





### Signature Standards


### ECDSA ALGORITHM


### TRANSACTION TYPES


### IMPLEMENT SIGNATURES ON-CHAIN








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