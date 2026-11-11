import { createHash, createPublicKey, verify } from "node:crypto";
import { Gas, parseGas, type KeyPair } from "near-kit";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_MAP = new Map<string, number>(
  BASE58_ALPHABET.split("").map((ch, idx) => [ch, idx]),
);

export function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const digits = [0];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let output = "";
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    output += BASE58_ALPHABET[0];
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    output += BASE58_ALPHABET[digits[i]];
  }
  return output;
}

export function decodeBase58(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);
  const bytes = [0];
  for (let i = 0; i < str.length; i++) {
    const val = BASE58_MAP.get(str[i]);
    if (val === undefined) {
      throw new Error(`Invalid base58 character: ${str[i]}`);
    }
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < str.length && str[i] === BASE58_ALPHABET[0]; i++) {
    bytes.push(0);
  }
  return Uint8Array.from(bytes.reverse());
}

class BorshWriter {
  private chunks: Buffer[] = [];

  u8(v: number): void {
    const b = Buffer.allocUnsafe(1);
    b.writeUInt8(v, 0);
    this.chunks.push(b);
  }

  u32(v: number): void {
    const b = Buffer.allocUnsafe(4);
    b.writeUInt32LE(v >>> 0, 0);
    this.chunks.push(b);
  }

  u64(v: bigint): void {
    const b = Buffer.allocUnsafe(8);
    b.writeBigUInt64LE(BigInt.asUintN(64, v), 0);
    this.chunks.push(b);
  }

  u128(v: bigint): void {
    const b = Buffer.allocUnsafe(16);
    const low = v & 0xffffffffffffffffn;
    const high = (v >> 64n) & 0xffffffffffffffffn;
    b.writeBigUInt64LE(low, 0);
    b.writeBigUInt64LE(high, 8);
    this.chunks.push(b);
  }

  fixedBytes(bytes: Uint8Array): void {
    this.chunks.push(Buffer.from(bytes));
  }

  bytes(bytes: Uint8Array): void {
    this.u32(bytes.length);
    this.chunks.push(Buffer.from(bytes));
  }

  string(text: string): void {
    const utf8 = Buffer.from(text, "utf8");
    this.u32(utf8.length);
    this.chunks.push(utf8);
  }

  finish(): Uint8Array {
    return Uint8Array.from(Buffer.concat(this.chunks));
  }
}

export interface FunctionCallTxInput {
  signerId: string;
  receiverId: string;
  methodName: string;
  args: Record<string, unknown>;
  gas?: Parameters<typeof parseGas>[0];
  attachedDepositYocto?: bigint;
  nonce: bigint;
  blockHashBase58: string;
  keyPair: KeyPair;
}

/**
 * Serializes a canonical NEAR V0 Transaction carrying a single FunctionCall Action,
 * computes its SHA-256 hash, signs with an Ed25519 KeyPair, and verifies the Ed25519
 * signature using Node's native WebCrypto/SPKI verifier.
 */
export function buildAndSignFunctionCallTx(input: FunctionCallTxInput): {
  txHash: string;
  signatureBase58: string;
  serializedSignedTx: Uint8Array;
  argsJson: string;
  gasUnits: string;
  signatureVerified: boolean;
} {
  if (input.keyPair.publicKey.data.length !== 32) {
    throw new Error("Expected 32-byte Ed25519 public key");
  }
  const blockHash = decodeBase58(input.blockHashBase58);
  if (blockHash.length !== 32) {
    throw new Error(`Expected 32-byte NEAR blockHash, got ${blockHash.length}`);
  }

  const argsJson = JSON.stringify(input.args);
  const argsBytes = Buffer.from(argsJson, "utf8");
  const gasStr = parseGas(input.gas ?? Gas.Tgas(30));
  const gasUnits = BigInt(gasStr);
  const depositYocto = input.attachedDepositYocto ?? 0n;

  const w = new BorshWriter();
  w.string(input.signerId);
  w.u8(0); // PublicKey::ED25519 discriminant
  w.fixedBytes(input.keyPair.publicKey.data);
  w.u64(input.nonce);
  w.string(input.receiverId);
  w.fixedBytes(blockHash);
  // Vec<Action> length = 1
  w.u32(1);
  // Action::FunctionCall discriminant = 2 (CreateAccount=0, DeployContract=1, FunctionCall=2)
  w.u8(2);
  w.string(input.methodName);
  w.bytes(argsBytes);
  w.u64(gasUnits);
  w.u128(depositYocto);

  const txBytes = w.finish();
  const txHashDigest = Uint8Array.from(createHash("sha256").update(txBytes).digest());
  const txHash = encodeBase58(txHashDigest);

  const sig = input.keyPair.sign(txHashDigest);
  const signatureBase58 = `ed25519:${encodeBase58(sig.data)}`;

  // Wrap as SignedTransaction { transaction, signature }
  const sw = new BorshWriter();
  sw.fixedBytes(txBytes);
  sw.u8(0); // Signature::ED25519
  sw.fixedBytes(sig.data);
  const serializedSignedTx = sw.finish();

  // Verify the Ed25519 signature cryptographically using Node crypto SPKI DER wrapper
  // RFC 8410 Ed25519 SubjectPublicKeyInfo prefix: 302a300506032b6570032100 + 32 bytes
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const spkiDer = Buffer.concat([spkiPrefix, Buffer.from(input.keyPair.publicKey.data)]);
  const pubKeyObj = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
  const signatureVerified = verify(null, txHashDigest, pubKeyObj, sig.data);

  return {
    txHash,
    signatureBase58,
    serializedSignedTx,
    argsJson,
    gasUnits: gasUnits.toString(),
    signatureVerified,
  };
}
