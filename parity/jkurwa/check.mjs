// Cross-checks the uacrypto cases against jkurwa (DSTU 4145) and gost89
// (GOST 34.311, GOST 28147), the JavaScript libraries of dstucrypt.
//
//	bun check.mjs cases.txt jkurwa_sigs.txt
//
// jkurwa defines three of the ten DSTU 4145 curves (191, 257 and 431 bits);
// signature cases on the others are skipped. jkurwa refuses to sign a zero
// hash, which DSTU 4145 replaces with 1, so zero-hash cases are skipped too.
import { readFileSync, writeFileSync } from "node:fs";
import gost89 from "gost89";
import { std_curve } from "jkurwa";

const curves = { 4: "DSTU_PB_191", 6: "DSTU_PB_257", 9: "DSTU_PB_431" };
const hex = (s) => (s === "-" ? Buffer.alloc(0) : Buffer.from(s, "hex"));
const str = (b) => (b.length === 0 ? "-" : Buffer.from(b).toString("hex"));

const stats = new Map();
function check(what, ok, detail) {
  const c = stats.get(what) ?? [0, 0];
  c[ok ? 0 : 1]++;
  stats.set(what, c);
  if (!ok) console.error("MISMATCH", what, detail);
}

// verify reports a rejected signature as false; jkurwa throws on some of them.
function verify(pub, hash, sig) {
  try {
    return pub.verify(hash, sig, "le");
  } catch {
    return false;
  }
}

const out = [];
let skipped = 0;
let macOneBlock = 0;
let emptyGost = 0;
for (const line of readFileSync(process.argv[2], "utf8").split("\n")) {
  const f = line.split(" ");
  switch (f[0]) {
    case "H":
      // gost89 hashes no padding block for the empty
      // message; uacrypto, cryptonite and UAPKI hash a zero block.
      if (f[1] === "-") {
        emptyGost++;
        break;
      }
      check("gost34311", str(gost89.gosthash(hex(f[1]))) === f[2], line.slice(0, 60));
      break;
    case "C": {
      const ctx = gost89.init();
      ctx.key(hex(f[1]));
      const ct = new Uint8Array(8);
      ctx.crypt64(hex(f[2]), ct);
      check("gost28147", str(ct) === f[3], line);
      break;
    }
    case "G": {
      // GOST 28147 modes under DKE No 1: key iv msg cfb mac32 mac64
      const ctx = gost89.init();
      ctx.key(hex(f[1]));
      const msg = hex(f[3]);
      if (msg.length > 0) {
        check("gost28147 cfb encrypt", str(ctx.crypt_cfb(hex(f[2]), msg)) === f[4], line.slice(0, 60));
        check("gost28147 cfb decrypt", str(ctx.decrypt_cfb(hex(f[2]), hex(f[4]))) === f[3], line.slice(0, 60));
      }
      // gost89 MACs a one-block message over that block and a zero block,
      // as the OpenSSL GOST engine does; uacrypto MACs the block alone.
      if (msg.length === 8) {
        macOneBlock++;
        break;
      }
      check("gost28147 mac 32", str(ctx.mac(32, msg)) === f[5], line.slice(0, 60));
      check("gost28147 mac 64", str(ctx.mac(64, msg)) === f[6], line.slice(0, 60));
      break;
    }
    case "S": {
      const hash = hex(f[5]);
      if (!curves[f[1]] || hash.every((b) => b === 0)) {
        skipped++;
        break;
      }
      const at = `curve ${f[1]} #${f[2]}`;
      const curve = std_curve(curves[f[1]]);
      const priv = curve.pkey(f[3], "hex");
      const q = Buffer.from(priv.pub().compress()).subarray(-Math.ceil(curve.m / 8));
      check("dstu4145 public key from d", str(q) === f[4], at);
      const pub = curve.pubkey(hex(f[4]), "buf8");
      check("dstu4145 decode Go key", pub.point.equals(priv.pub().point), at);
      check("dstu4145 verify Go signature", verify(pub, hash, hex(f[8])), at);
      // r||s, each little-endian, as IIT writes it
      const rs = priv.sign(hash, "le");
      const half = rs.length / 2;
      const be = (b) => Buffer.from(b).reverse().toString("hex");
      out.push(`X jkurwa ${f[1]} ${f[4]} ${f[5]} ${be(rs.subarray(0, half))} ${be(rs.subarray(half))}`);
      break;
    }
  }
}
writeFileSync(process.argv[3], out.map((l) => l + "\n").join(""));

let failed = false;
for (const [what, [ok, bad]] of [...stats].sort()) {
  console.log(`jkurwa   ${what.padEnd(32)} ${String(ok).padStart(4)} ok ${bad} mismatch`);
  failed ||= bad > 0;
}
console.log(`jkurwa   skipped ${skipped} signature cases: curve not in jkurwa or zero hash`);
console.log(`jkurwa   skipped ${macOneBlock} one-block MAC cases: gost89 appends a zero block`);
console.log(`jkurwa   skipped ${emptyGost} empty-message GOST 34.311 cases: gost89 hashes no padding block`);
process.exit(failed ? 1 : 0);
