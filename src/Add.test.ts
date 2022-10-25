import { Add } from './Add';
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
} from 'snarkyjs';

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

function createLocalBlockchain() {
  const Local = Mina.LocalBlockchain();
  Mina.setActiveInstance(Local);
  return Local.testAccounts[0].privateKey;
}
async function localDeploy(
  zkAppInstance: Add,
  zkAppPrivatekey: PrivateKey,
  deployerAccount: PrivateKey
) {
  const txn = await Mina.transaction(deployerAccount, () => {
    AccountUpdate.fundNewAccount(deployerAccount);
    zkAppInstance.deploy({ zkappKey: zkAppPrivatekey });
    zkAppInstance.init();
    zkAppInstance.sign(zkAppPrivatekey);
  });
  await txn.send().wait();
}

describe('Add', () => {
  let deployerAccount: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey;

  let tag: Field[];
  beforeEach(async () => {
    await isReady;
    deployerAccount = createLocalBlockchain();
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    tag = Encoding.stringToFields('tag');
  });

  afterAll(async () => {
    // `shutdown()` internally calls `process.exit()` which will exit the running Jest process early.
    // Specifying a timeout of 0 is a workaround to defer `shutdown()` until Jest is done running all tests.
    // This should be fixed with https://github.com/MinaProtocol/mina/issues/10943
    setTimeout(shutdown, 0);
  });

  it('generates and deploys the `Add` smart contract', async () => {
    const zkAppInstance = new Add(zkAppAddress);
    await localDeploy(zkAppInstance, zkAppPrivateKey, deployerAccount);
    const num = zkAppInstance.num.get();
    expect(num).toEqual(Field.one);
  });

  it('correctly updates the num state on the `Add` smart contract', async () => {
    const zkAppInstance = new Add(zkAppAddress);
    await localDeploy(zkAppInstance, zkAppPrivateKey, deployerAccount);
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.update();
      zkAppInstance.sign(zkAppPrivateKey);
    });
    await txn.send().wait();

    const updatedNum = zkAppInstance.num.get();
    expect(updatedNum).toEqual(Field(3));
  });

  it.only('correctly encrypts the data', async () => {
    // Encrypt
    const t = Scalar.random();
    const T = Group.generator.scale(t);

    const h = Poseidon.hash(tag.concat(zkAppPrivateKey.toFields())).toBits();
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

    // Decrypt
    const xb = zkAppPrivateKey.toFields();
    // TODO(@ckartik): Check the checksum
    const h_ = Scalar.ofBits(Poseidon.hash(tag.concat(xb)).toBits());
    const hG_ = Group.generator.scale(h_);

    const encryptedKey_ = encryptedKey;
    const T_ = encryptedKey_.sub(hG_);
    const Tbuf_ = Group.toFields(T_);
    const key_ = Poseidon.hash(Tbuf_);

    // Decryption
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
