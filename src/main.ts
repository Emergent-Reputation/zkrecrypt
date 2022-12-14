import { ReEncrypt } from './ReEncrypt.js';
import {
  isReady,
  shutdown,
  Mina,
  PrivateKey,
  AccountUpdate,
  Experimental,
  Field,
  Poseidon,
  Group,
  Scalar,
} from 'snarkyjs';

(async function main() {
  console.log('waiting to be ready.');
  await isReady;
  console.log('Snarky has loaded');

  const Local = Mina.LocalBlockchain();
  Mina.setActiveInstance(Local);
  const deployerAccount = Local.testAccounts[0].privateKey;
  const alicePrivateKey = PrivateKey.random();
  const zkAppPrivateKey = PrivateKey.random();
  const zkAppAddress = zkAppPrivateKey.toPublicKey();

  const contract = new ReEncrypt(zkAppAddress);
  const height = 20;
  const tree = new Experimental.MerkleTree(height);

  class MerkleWitness extends Experimental.MerkleWitness(height) {}

  const deployTxn = await Mina.transaction(deployerAccount, () => {
    AccountUpdate.fundNewAccount(deployerAccount);
    contract.deploy({ zkappKey: zkAppPrivateKey });
    contract.init(tree.getRoot(), alicePrivateKey, Field(1));
    contract.sign(zkAppPrivateKey);
  });
  await deployTxn.send().wait();

  var nextIndex = contract.nextIndex.get();

  const witness = new MerkleWitness(tree.getWitness(nextIndex.toBigInt()));
  console.log(contract.treeRoot.get().toString());

  const h = Scalar.ofBits(
    Poseidon.hash([Field(1)].concat(alicePrivateKey.toFields())).toBits()
  );
  const hG = Group.generator.scale(h);

  const encKey = contract.encryptedSymmetricKey.get();
  let sponge = new Poseidon.Sponge();
  const key = encKey.sub(hG);
  sponge.absorb(key.x);
  sponge.absorb(key.y);

  // Resulting encrypted payload
  let encryptedData = Field(666).add(sponge.squeeze());
  tree.setLeaf(nextIndex.toBigInt(), encryptedData);

  const txn1 = await Mina.transaction(deployerAccount, () => {
    contract.addData(Field(666), witness, alicePrivateKey);
    contract.sign(zkAppPrivateKey);
  });
  await txn1.send().wait();

  console.log('Local Tree Root:  ', tree.getRoot().toString());
  console.log('Remote Tree Root: ', contract.treeRoot.get().toString());

  let sponge2 = new Poseidon.Sponge();
  sponge2.absorb(key.x);
  sponge2.absorb(key.y);

  // Resulting encrypted payload
  console.log(
    'Decrypted data should be 666: ',
    encryptedData.sub(sponge2.squeeze()).toString()
  );

  // const encryptTxn = await Mina.transaction(deployerAccount, () => {
  //   contract.encrypt(alicePrivateKey)
  //   contract.sign(zkAppPrivateKey);
  // });

  // await encryptTxn.send().wait();
  // const str = await contract.cipher.get();
  // console.log("Cipher is: ", str);

  await shutdown();
  // const num0 = contract.num.get();
  // console.log('state after init:', num0.toString());
  // const updateTxn = await Mina.transaction(deployerAccount, () => {
  //   contract.update(Field(9));
  //   contract.sign(zkAppPrivateKey);
  // });
  // await updateTxn.send().wait();

  // try {
  //   const txn3 = await Mina.transaction(deployerAccount, () => {
  //     contract.update(Field(81));
  //     contract.sign(zkAppPrivateKey);
  //   });
  //   await txn3.send().wait();
  // } catch (err: any) {
  //   console.log(err.message);
  // }

  // const num1 = contract.num.get();
  // console.log('state at the end:', num1.toString());
  // console.log('Shutting down');
})();
