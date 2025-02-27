import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import fs from "fs";

// (1)
const tree = StandardMerkleTree.load(JSON.parse(fs.readFileSync("tree.json", "utf8")));

// (2) on frontend we can enable the gas payer to access the proofs by passing the address details
for (const [i, v] of tree.entries()) {
  if (v[0] === '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266') {
    // (3)
    const proof = tree.getProof(i);
    console.log('Value:', v);
    console.log('Proof:', proof);
    // writing proof for address(account) in proof.json
    fs.writeFileSync("proof.json", JSON.stringify(proof));
  }
}