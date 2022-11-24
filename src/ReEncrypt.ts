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

    // Get random initializer value
    const r = Scalar.random();
    // Derive the symmetric key
    const symkey = Group.generator.scale(r);

    // Set the tag at the top level
    this.tag.set(tag);

    // Construct a determinstic element of the group repd by EC(F_P).
    const h = Scalar.ofBits(
      Poseidon.hash(tag.toFields().concat(alicePrivateKey.toFields())).toBits()
    );
    const hG = Group.generator.scale(h);

    // Set the sym key approperiately
    this.encryptedSymmetricKey.set(symkey.add(hG));

    // Hash of symkey is stored for integirty checks during data updates.
    this.symKeyHash.set(Poseidon.hash(Group.toFields(symkey)));

    // Set the merkle root hash to zero value
    this.treeRoot.set(initRoot);

    // Set index for data entry to zero value
    this.nextIndex.set(Field(0));
  }

  // Currently only supports append-only operations.

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
    const sk = encryptedKey.sub(hG);

    const sharedKey = bobPubKey
      .toGroup()
      .scale(Scalar.ofFields(alicePrivateKey.toFields()));

    const hs = sk.add(sharedKey);
    this.reEncryptedKey.set(hs);
  }
}
