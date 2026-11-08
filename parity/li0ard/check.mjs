// Cross-checks the uacrypto cases against @li0ard/dstu, DSTU algorithms in
// pure TypeScript (Kupyna, Kalyna, DSTU 4145; no GOST 34.311 or GOST 28147).
//
//	bun check.mjs cases.txt li0ard_sigs.txt
//
// li0ard/dstu follows the letter of DSTU 4145: the hash is a big-endian
// number and a signature is s||r, each big-endian. uacrypto and IIT read
// the hash as little-endian, so it is reversed on the way in.
import { readFileSync, writeFileSync } from "node:fs";
import {
  dstu163, dstu167, dstu173, dstu179, dstu191, dstu233, dstu257, dstu307, dstu367, dstu431,
  Kalyna128, Kalyna128_256, Kalyna256, Kalyna256_512, Kalyna512,
  kupyna256, kupyna384, kupyna512,
} from "@li0ard/dstu";

const curves = [dstu163, dstu167, dstu173, dstu179, dstu191, dstu233, dstu257, dstu307, dstu367, dstu431];
const kalynas = {
  "16/16": Kalyna128, "16/32": Kalyna128_256, "32/32": Kalyna256, "32/64": Kalyna256_512, "64/64": Kalyna512,
};
const hex = (s) => (s === "-" ? Buffer.alloc(0) : Buffer.from(s, "hex"));
const str = (b) => (b.length === 0 ? "-" : Buffer.from(b).toString("hex"));
const reversed = (b) => Buffer.from(b).reverse();

const stats = new Map();
function check(what, ok, detail) {
  const c = stats.get(what) ?? [0, 0];
  c[ok ? 0 : 1]++;
  stats.set(what, c);
  if (!ok) console.error("MISMATCH", what, detail);
}

const out = [];
for (const line of readFileSync(process.argv[2], "utf8").split("\n")) {
  const f = line.split(" ");
  const at = line.slice(0, 60);
  switch (f[0]) {
    case "H": {
      const msg = hex(f[1]);
      check("kupyna256", str(kupyna256(msg)) === f[3], at);
      check("kupyna384", str(kupyna384(msg)) === f[4], at);
      check("kupyna512", str(kupyna512(msg)) === f[5], at);
      break;
    }
    case "K": {
      // key plaintext ciphertext; the block size is the plaintext length
      const key = hex(f[1]), pt = hex(f[2]);
      const block = new kalynas[`${pt.length}/${key.length}`](key);
      const name = `kalyna ${8 * pt.length}/${8 * key.length}`;
      check(`${name} encrypt`, str(block.encrypt(pt)) === f[3], at);
      check(`${name} decrypt`, str(block.decrypt(hex(f[3]))) === f[2], at);
      break;
    }
    case "S": {
      // curve index d Q hash r s r||s
      const at = `curve ${f[1]} #${f[2]}`;
      const signer = curves[f[1]];
      const n = signer.lengths.scalarByteLength;
      const d = Buffer.from(f[3].padStart(2 * n, "0"), "hex");
      check("dstu4145 public key from d", str(signer.getPublicKey(d)) === f[4], at);
      const digest = reversed(hex(f[5]));
      const be = (s) => Buffer.from(s.padStart(2 * n, "0"), "hex");
      let ok;
      try {
        ok = signer.verify(hex(f[4]), digest, Buffer.concat([be(f[7]), be(f[6])]));
      } catch {
        ok = false;
      }
      check("dstu4145 verify Go signature", ok, at);
      const sr = signer.sign(d, digest);
      const strip = (b) => Buffer.from(b).toString("hex").replace(/^0+(?=.)/, "");
      out.push(`X li0ard ${f[1]} ${f[4]} ${f[5]} ${strip(sr.subarray(n))} ${strip(sr.subarray(0, n))}`);
      break;
    }
  }
}
writeFileSync(process.argv[3], out.map((l) => l + "\n").join(""));

let failed = false;
for (const [what, [ok, bad]] of [...stats].sort()) {
  console.log(`li0ard   ${what.padEnd(32)} ${String(ok).padStart(4)} ok ${bad} mismatch`);
  failed ||= bad > 0;
}
process.exit(failed ? 1 : 0);
