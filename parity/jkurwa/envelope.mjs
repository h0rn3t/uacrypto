// Cross-checks the CMS EnvelopedData of uacrypto against jkurwa: decrypts the
// envelopes of `parity envelope-gen` and, where both keys are on one curve
// (jkurwa agrees only with the sender's own key), sends the content back from
// the recipient to the sender for `parity envelope-check`.
//
//	bun envelope.mjs go_env.txt jkurwa_env.txt
import { readFileSync, writeFileSync } from "node:fs";
import gost89 from "gost89";
import { std_curve, Certificate, models } from "jkurwa";

const curves = { 4: "DSTU_PB_191", 6: "DSTU_PB_257", 9: "DSTU_PB_431" };
const hex = (s) => (s === "-" ? Buffer.alloc(0) : Buffer.from(s, "hex"));
const algo = gost89.compat.algos();

let ok = 0;
let bad = 0;
const out = [];
const lines = readFileSync(process.argv[2], "utf8").split("\n").filter((l) => l.startsWith("E "));
lines.forEach((line, i) => {
  const [, sc, sd, scert, rc, rd, rcert, content, env] = line.split(" ");
  const sender = Certificate.from_asn1(hex(scert));
  const recipient = Certificate.from_asn1(hex(rcert));
  const recipientKey = std_curve(curves[rc]).pkey(rd, "hex");
  try {
    const msg = new models.Message(hex(env));
    const got = msg.decrypt(recipientKey, algo, () => sender);
    if (Buffer.compare(Buffer.from(got), hex(content)) === 0) {
      ok++;
    } else {
      bad++;
      console.error("MISMATCH jkurwa decrypt of uacrypto envelope", i, "content differs");
    }
  } catch (e) {
    bad++;
    console.error("MISMATCH jkurwa decrypt of uacrypto envelope", i, e.message);
  }
  if (sc !== rc) {
    return;
  }
  const back = new models.Message({
    type: "envelopedData",
    cert: recipient,
    toCert: sender,
    data: hex(content),
    crypter: recipientKey,
    algo,
  });
  out.push(`J ${i} ${back.as_asn1().toString("hex")}`);
});
writeFileSync(process.argv[3], out.map((l) => l + "\n").join(""));

console.log(`jkurwa   ${"decrypt uacrypto envelope".padEnd(32)} ${String(ok).padStart(4)} ok ${bad} mismatch`);
if (bad > 0 || ok === 0) {
  process.exit(1);
}
