import { ReEncrypt } from './ReEncrypt';
import {
  isReady,
  shutdown,
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  Group,
  Poseidon,
  Scalar,
  Encoding,
  Experimental,
} from 'snarkyjs';

// type ReEncryptedMessage = {
//   D1: Buffer;                 //  Point
//   D2: Buffer;
//   D3: Buffer;
//   D4: Buffer;                 //  Point
//   D5: Buffer;                 //  Point
// }

/**
 * @internal
 * @param args -
 */

/*
 * This file specifies how to test the `Add` example smart contract. It is safe to delete this file and replace
 * with your own tests.
 *
 * See https://docs.minaprotocol.com/zkapps for more info.
 */
const height = 20;
class MerkleWitness extends Experimental.MerkleWitness(height) {}

function createLocalBlockchain() {
  const Local = Mina.LocalBlockchain();
  Mina.setActiveInstance(Local);
  return Local.testAccounts[0].privateKey;
}
async function localDeploy(
  contract: ReEncrypt,
  zkAppPrivateKey: PrivateKey,
  deployerAccount: PrivateKey,
  alicePrivateKey: PrivateKey
) {
  const tree = new Experimental.MerkleTree(height);

  const deployTxn = await Mina.transaction(deployerAccount, () => {
    AccountUpdate.fundNewAccount(deployerAccount);
    contract.deploy({ zkappKey: zkAppPrivateKey });
    contract.init(tree.getRoot(), alicePrivateKey, Field(1));
    contract.sign(zkAppPrivateKey);
  });
  await deployTxn.send().wait();
}

describe('Add', () => {
  let deployerAccount: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    alicePrivateKey: PrivateKey;
  let tag: Field[];
  beforeEach(async () => {
    await isReady;
    deployerAccount = createLocalBlockchain();
    zkAppPrivateKey = PrivateKey.random();
    alicePrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    tag = Encoding.stringToFields('tag');
  });

  afterAll(async () => {
    setTimeout(shutdown, 0);
  });

  it('creates encrypted payload', async () => {
    // We want to ensure here that a contract is deployed, so we can
    // interact with it later in this test
    const contract = new ReEncrypt(zkAppAddress);
    await localDeploy(
      contract,
      zkAppPrivateKey,
      deployerAccount,
      alicePrivateKey
    );

    const alicePubKey = alicePrivateKey.toPublicKey();
    const tree = new Experimental.MerkleTree(height);

    var nextIndex = contract.nextIndex.get();

    const witness = new MerkleWitness(tree.getWitness(nextIndex.toBigInt()));
    console.log(contract.treeRoot.get().toString());

    const h = Scalar.ofBits(
      Poseidon.hash([Field(1)].concat(alicePrivateKey.toFields())).toBits()
    );
    const hG = Group.generator.scale(h);

    const encKey = contract.encryptedSymmetricKey.get();
    const key = encKey.sub(hG);
    let sponge = new Poseidon.Sponge();
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

    tree.getRoot().assertEquals(contract.treeRoot.get());

    console.log('Local Tree Root:  ', tree.getRoot().toString());
    console.log('Remote Tree Root: ', contract.treeRoot.get().toString());

    let sponge2 = new Poseidon.Sponge();
    sponge2.absorb(key.x);
    sponge2.absorb(key.y);

    const decryptedPlainText = encryptedData.sub(sponge2.squeeze());
    decryptedPlainText.assertEquals(Field(666));

    // Resulting encrypted payload
    console.log(
      'Decrypted data should be 666: ',
      decryptedPlainText.toString()
    );

    const bobPrivKey = PrivateKey.random();
    const bobPubKey = bobPrivKey.toPublicKey();
    // alice sends txn to convert key
    const txnReCrypt = await Mina.transaction(deployerAccount, () => {
      contract.generateReKey(alicePrivateKey, bobPubKey);
      contract.sign(zkAppPrivateKey);
    });
    await txnReCrypt.send().wait();

    // bob land gets key and discoveres sym key.
    const bobReKey = contract.reEncryptedKey.get();
    const sk = alicePubKey
      .toGroup()
      .scale(Scalar.ofFields(bobPrivKey.toFields()));
    const keybob = bobReKey.sub(sk);
    keybob.assertEquals(key);
  });

  it('correctly creates secret key exchange', async () => {
    const a = PrivateKey.random();
    const b = PrivateKey.random();

    const aG = a.toPublicKey();
    const bG = b.toPublicKey();

    aG.toGroup()
      .scale(Scalar.ofFields(b.toFields()))
      .assertEquals(bG.toGroup().scale(Scalar.ofFields(a.toFields())));
  });

  it('correctly encrypts the data', async () => {
    // Encrypt
    const t = Scalar.random(); // tmp private key
    const T = Group.generator.scale(t); // tmp public key

    const h = Poseidon.hash(tag.concat(zkAppPrivateKey.toFields())).toBits(); //
    const hG = Group.generator.scale(Scalar.ofBits(h));
    // TODO(@ckartik): Can't seem to set encrypted key into bits
    const encryptedKey = T.add(hG);
    const Tbuf = Group.toFields(T);

    const key = Poseidon.hash(Tbuf);

    let sponge = new Poseidon.Sponge();
    sponge.absorb(key);
    const message = Encoding.stringToFields('Happy Diwali!');

    // encryption
    let cipherText: Field[] = [];
    for (let i = 0; i < message.length; i++) {
      let keyStream = sponge.squeeze();
      let encryptedChunk = message[i].add(keyStream);
      cipherText.push(encryptedChunk);
      // absorb for the auth tag (two at a time for saving permutations)
      if (i % 2 === 1) sponge.absorb(cipherText[i - 1]);
      if (i % 2 === 1 || i === message.length - 1) sponge.absorb(cipherText[i]);
    }
    // authentication tag
    let authenticationTag = sponge.squeeze();
    cipherText.push(authenticationTag);
    // TODO(@ckartik): Create a checksum here

    // REKey Generation
    /*
    Start of Re Key Generation

    const bobPrivKey = PrivateKey.random();
    const bobPubKey = bobPrivKey.toPublicKey();
    const r_rekey = Scalar.random();

    const privKey = zkAppPrivateKey;
    const h_rekey = Poseidon.hash(tag.concat(privKey.toFields()));

    // R1 Generation
    const R1 = Group.generator.scale(r_rekey.sub(Scalar.ofFields(h_rekey)));
    // R2 Geneartion

    const R2 = bobPubKey.toGroup().scale(r_rekey); //  rP = rxG

    const R3 = Scalar.ofFields(Field.toFields(h_rekey));

    // For Linter to shut-up.
    R1;
    R2;
    R3;

    End of Re-Key Generation
    */

    /*
      Re-Decrypt

    const check1 = sha512(
      msg.encryptedKey,
      msg.data,
      msg.messageChecksum,
      rekey.R3
  );

  if (!check1.equals(msg.overallChecksum)) {
      throw new OverallChecksumFailure();
  }

  const P = curve.pointFromBuffer(publicKey);
  const t = curve.randomScalar();
  const txG = P.mul(t);                                                   //  tP = txG

  const res: Partial<ReEncryptedMessage> = {};
  res.D2 = msg.data;
  res.D3 = msg.messageChecksum;
  res.D4 = rekey.R2;
  res.D5 = curve.basepoint.mul(t).toBuffer()                              //  tG

  //  hash7
  const bet = curve.scalarFromHash(
      txG.toBuffer(),
      res.D2,
      res.D3,
      res.D4,
      res.D5
  );

  const R1 = curve.pointFromBuffer(rekey.R1);
  const encryptedKey = curve.pointFromBuffer(msg.encryptedKey).add(R1);
  res.D1 = encryptedKey.mul(bet).toBuffer();

  return res as ReEncryptedMessage;
    copied re-encrypt
  */

    // Decrypt
    const xb = zkAppPrivateKey.toFields();
    // TODO(@ckartik): Check the checksum
    const h_ = Scalar.ofBits(Poseidon.hash(tag.concat(xb)).toBits());
    const hG_ = Group.generator.scale(h_);

    const encryptedKey_ = encryptedKey;
    const T_ = encryptedKey_.sub(hG_);
    const Tbuf_ = Group.toFields(T_);
    const key_ = Poseidon.hash(Tbuf_);

    // Poseidon Decryption
    let sponge_ = new Poseidon.Sponge();
    sponge_.absorb(key_);
    let authenticationTag_ = cipherText.pop();

    // decryption
    let message_: Field[] = [];
    for (let i = 0; i < cipherText.length; i++) {
      let keyStream = sponge_.squeeze();
      let messageChunk = cipherText[i].sub(keyStream);
      message_.push(messageChunk);
      if (i % 2 === 1) sponge_.absorb(cipherText[i - 1]);
      if (i % 2 === 1 || i === cipherText.length - 1)
        sponge_.absorb(cipherText[i]);
    }
    sponge_.squeeze().assertEquals(authenticationTag_!);

    console.log(Encoding.stringFromFields(message));
    console.log(Encoding.stringFromFields(message_));

    // console.log(Encoding.stringFromFields(message_))
  });
});
// Example of using encrytption decryption in snarky
// https://github.com/o1-labs/snarkyjs/blob/3cf7dbd551492af0ab4a49bd2573345464ebea9e/src/examples/encryption.ts#L64

// Defn of encrypt decrypt utility
// https://github.com/o1-labs/snarkyjs/blob/main/src/lib/encryption.ts
