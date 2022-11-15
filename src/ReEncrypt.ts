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
  // Poseidon,
  // Scalar,
  // Encoding,
  // CircuitString,
  Experimental,
  Poseidon,
  // Circuit,
  // PrivateKey,
} from 'snarkyjs';

class MerkleWitness20 extends Experimental.MerkleWitness(20) {}

export class ReEncrypt extends SmartContract {
  // This will represent the key that should be re-encrypted for others.
  // This is Alice's symmetric key encrypted
  @state(Group) encryptedSymmetricKey = State<Group>();
  @state(Field) cipher = State<Field>();

  // This will be Bob's key once we re-encrypt it from `encryptedSymmetricKey`
  @state(Group) reEncryptedKey = State<Group>();

  // Stores a hash of the symKey to ensure integirty of updates
  @state(Field) symKeyHash = State<Field>();

  @state(Field) treeRoot = State<Field>();
  @state(Field) nextIndex = State<Field>();

  deploy(args: DeployArgs) {
    super.deploy(args);
    this.setPermissions({
      ...Permissions.default(),
      editState: Permissions.proofOrSignature(),
    });
  }

  // Does nothing
  @method init(initRoot: Field) {
    // We init an empty MerkleTree on initialization.
    // Init Sym Key
    const symPrivKey = Scalar.random(); // tmp private key

    // Derive the pubkey
    const symPubKey = Group.generator.scale(symPrivKey);

    this.symKeyHash.set(Poseidon.hash(Group.toFields(symPubKey)));

    this.treeRoot.set(initRoot);
    this.nextIndex.set(Field(0));
  }

  @method addData(data: Field, witness: MerkleWitness20) {
    // TODO(@ckartik): Encrypt the data
    // let sponge = new Poseidon.Sponge();
    // sponge.absorb(key);
    // let encryptedData = data.add(keyStream);

    // Update the tree leafs
    const currRoot = this.treeRoot.get();
    this.treeRoot.assertEquals(currRoot);
    this.nextIndex.assertEquals(witness.calculateIndex());

    // Set new root for data
    // Note the actual data needs to be added externally
    const newRoot = witness.calculateRoot(data);
    this.treeRoot.set(newRoot);

    // Set new Index
    const currIndex = this.nextIndex.get();
    this.nextIndex.assertEquals(currIndex);
    this.nextIndex.set(currIndex.add(Field(1)));
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
