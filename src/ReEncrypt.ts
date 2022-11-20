import {
  Field,
  SmartContract,
  state,
  State,
  method,
  DeployArgs,
  Permissions,
  Group,
  Scalar,
  // Encoding,
  // CircuitString,
  Experimental,
  Poseidon,
  PrivateKey,
  PublicKey,
  // Circuit,
  // PrivateKey,
} from 'snarkyjs';

class MerkleWitness20 extends Experimental.MerkleWitness(20) {}

export class ReEncrypt extends SmartContract {
  // This will represent the key that should be re-encrypted for others.
  // This is Alice's symmetric key encrypted
  @state(Group) encryptedSymmetricKey = State<Group>();

  // This will be Bob's key once we re-encrypt it from `encryptedSymmetricKey`
  @state(Group) reEncryptedKey = State<Group>();

  // Stores a hash of the symKey to ensure integirty of updates
  @state(Field) symKeyHash = State<Field>();
  @state(Field) tag = State<Field>();
  @state(Field) treeRoot = State<Field>();
  @state(Field) nextIndex = State<Field>();

  deploy(args: DeployArgs) {
    super.deploy(args);
    this.setPermissions({
      ...Permissions.default(),
      editState: Permissions.proofOrSignature(),
    });
  }

  @method init(initRoot: Field, alicePrivateKey: PrivateKey, tag: Field) {
    // We init an empty MerkleTree on initialization.

    // Init Sym Key
    const symPrivKey = Scalar.random(); // tmp private key
    // Derive the pubkey
    const symPubKey = Group.generator.scale(symPrivKey);

    // Set the tag at the top level
    this.tag.set(tag);

    // Construct a determinstic element of the group repd by EC(F_P).
    const h = Scalar.ofBits(
      Poseidon.hash(tag.toFields().concat(alicePrivateKey.toFields())).toBits()
    );
    const hG = Group.generator.scale(h);

    // Set the sym key approperiately
    this.encryptedSymmetricKey.set(symPubKey.add(hG));

    // Hash of symkey is stored for integirty checks during data updates.
    this.symKeyHash.set(Poseidon.hash(Group.toFields(symPubKey)));

    // Set the merkle root hash to zero value
    this.treeRoot.set(initRoot);

    // Set index for data entry to zero value
    this.nextIndex.set(Field(0));
  }

  // Currently only supports append-only operations.
  // TODO(@ckartik): Think about dynamic access
  // We may want to pass in the last ciphertext and allow the Poseidon hash to obsorb it
  @method addData(
    data: Field,
    witness: MerkleWitness20,
    privateKey: PrivateKey
  ) {
    // TODO(@ckartik): Encrypt the data

    const tag = this.tag.get();
    this.tag.assertEquals(tag);

    const h = Scalar.ofBits(
      Poseidon.hash(tag.toFields().concat(privateKey.toFields())).toBits()
    );
    const hG = Group.generator.scale(h);

    const encryptedKey = this.encryptedSymmetricKey.get();
    this.encryptedSymmetricKey.assertEquals(encryptedKey);

    // LHS = encKey - hG = (key + hG) - hG = key QED
    const key = encryptedKey.sub(hG);

    // Generate KeyStream from Sym Key
    this.symKeyHash.assertEquals(Poseidon.hash(Group.toFields(key)));
    let sponge = new Poseidon.Sponge();
    //ATTACK There's not enough entropy here
    //ATTACK This will be decrypt susciptilbe to an attack given two pieces of ciphertext

    sponge.absorb(key.x);
    sponge.absorb(key.y);

    let encryptedData = data.add(sponge.squeeze());

    // Update the tree leafs
    const currRoot = this.treeRoot.get();
    this.treeRoot.assertEquals(currRoot);
    this.nextIndex.assertEquals(witness.calculateIndex());

    // Set new root for data
    // Note the actual data needs to be added externally
    const newRoot = witness.calculateRoot(encryptedData);
    this.treeRoot.set(newRoot);

    // Set new Index
    const currIndex = this.nextIndex.get();
    this.nextIndex.assertEquals(currIndex);
    this.nextIndex.set(currIndex.add(Field(1)));
  }

  @method async selfDecrypt(
    ciphertext: Field,
    witness: MerkleWitness20,
    alicePrivateKey: PrivateKey
  ) {
    const tag = this.tag.get();
    this.tag.assertEquals(tag);
    const encryptedKey = this.encryptedSymmetricKey.get();
    this.encryptedSymmetricKey.assertEquals(encryptedKey);

    const xb = alicePrivateKey.toFields();
    // TODO(@ckartik): Check the checksum
    const h = Scalar.ofBits(Poseidon.hash(tag.toFields().concat(xb)).toBits());
    const hG = Group.generator.scale(h);
    const T = encryptedKey.sub(hG);

    const key = Poseidon.hash(Group.toFields(T));

    // Poseidon Decryption
    let sponge = new Poseidon.Sponge();
    sponge.absorb(key);
    let keyStream = sponge.squeeze();
    const plaintext = ciphertext.sub(keyStream);
    plaintext;
  }

  @method async generateReKey(
    alicePrivateKey: PrivateKey,
    bobPubKey: PublicKey
  ) {
    const tag = this.tag.get();
    this.tag.assertEquals(tag);
    const encryptedKey = this.encryptedSymmetricKey.get();
    this.encryptedSymmetricKey.assertEquals(encryptedKey);

    const xb = alicePrivateKey.toFields();
    // TODO(@ckartik): Check the checksum
    const h = Scalar.ofBits(Poseidon.hash(tag.toFields().concat(xb)).toBits());
    const hG = Group.generator.scale(h);
    const T = encryptedKey.sub(hG);
    const sk = bobPubKey
      .toGroup()
      .scale(Scalar.ofFields(alicePrivateKey.toFields()));

    const hs = T.add(sk);

    this.reEncryptedKey.set(hs);
    this.reEncryptedKey.assertEquals(hs);
  }

  @method async grantAccessToData(
    bobPubKey: PublicKey,
    alicePrivateKey: PrivateKey
  ) {
    const tag = this.tag.get();
    this.tag.assertEquals(tag);

    const h = Scalar.ofBits(
      Poseidon.hash(tag.toFields().concat(alicePrivateKey.toFields())).toBits()
    );
    h;
    bobPubKey;
  }
  //   @method async storeEncryptionKey(privKey: PrivateKey) {
  //   }

  //   // TODO(@ckartik): Need to figure out how to send large plaintext into function.
  //   // or somehow prove that the payload encrypted
  //   @method async encrypt(privKey: PrivateKey) {
  //     const message = Encoding.stringToFields('Happy Diwali!');
  //     const tag = Encoding.stringToFields('tag');
  //     const t = Scalar.random(); // tmp private key
  //     const T = Group.generator.scale(t); // tmp public key

  //     const h = Poseidon.hash(tag.concat(privKey.toFields())).toBits(); //
  //     const hG = Group.generator.scale(Scalar.ofBits(h));
  //     // TODO(@ckartik): Can't seem to set encrypted key into bits
  //     const encryptedKey = T.add(hG);
  //     const Tbuf = Group.toFields(T);

  //     const key = Poseidon.hash(Tbuf);

  //     let sponge = new Poseidon.Sponge();
  //     sponge.absorb(key);

  //     // encryption
  //     let cipherText: Field[] = [];
  //     for (let i = 0; i < message.length; i++) {
  //       let keyStream = sponge.squeeze();
  //       let encryptedChunk = message[i].add(keyStream);
  //       cipherText.push(encryptedChunk);
  //       // absorb for the auth tag (two at a time for saving permutations)
  //       let absorbableData: Field[] = []

  //       /*
  //       Converts

  //       if (i % 2 === 1) sponge.absorb(cipherText[i - 1]);
  //       if (i % 2 === 1 || i === message.length - 1) sponge.absorb(cipherText[i]);

  //       into a circuit
  //       */
  //       absorbableData =  Circuit.if(i % 2 === 1, absorbableData.concat(cipherText[i - 1]), absorbableData)
  //       absorbableData =  Circuit.if(i % 2 === 1 || i === message.length - 1, absorbableData.concat(cipherText[i]), absorbableData)
  //       for (let j = 0; j < absorbableData.length; j++) {
  //         sponge.absorb(absorbableData[j])
  //       }
  //     }
  //     // authentication tag
  //     let authenticationTag = sponge.squeeze();
  //     cipherText.push(authenticationTag);

  // }
}
