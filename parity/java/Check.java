import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ua.*;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.DSTU4145Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class Check {
  static byte[] sbox() {
    byte[] dke = DSTU4145Params.getDefaultDKE(); byte[] s = new byte[128];
    for (int i = 0; i < 64; i++) { s[2*i] = (byte)((dke[i]>>4)&0xf); s[2*i+1] = (byte)(dke[i]&0xf); }
    return s;
  }
  static byte[] h(String s) { return s.equals("-") ? new byte[0] : Hex.decode(s); }
  static String x(byte[] b) { return b.length == 0 ? "-" : Hex.toHexString(b); }
  static Map<String,int[]> stats = new TreeMap<>();
  static void check(String what, boolean ok, String detail) {
    int[] c = stats.computeIfAbsent(what, k -> new int[2]); c[ok ? 0 : 1]++;
    if (!ok) System.err.println("MISMATCH " + what + " " + detail);
  }
  static byte[] digest(org.bouncycastle.crypto.Digest d, byte[] m) {
    d.update(m, 0, m.length); byte[] o = new byte[d.getDigestSize()]; d.doFinal(o, 0); return o;
  }
  public static void main(String[] a) throws Exception {
    BufferedReader in = new BufferedReader(new FileReader(a[0]));
    PrintWriter out = new PrintWriter(new FileWriter(a[1]));
    SecureRandom rnd = new SecureRandom();
    for (String line; (line = in.readLine()) != null; ) {
      String[] f = line.split(" ");
      switch (f[0]) {
        case "H": {
          byte[] m = h(f[1]);
          check("gost34311", x(digest(new GOST3411Digest(sbox()), m)).equals(f[2]), line.substring(0, Math.min(60, line.length())));
          check("kupyna256", x(digest(new DSTU7564Digest(256), m)).equals(f[3]), f[1].length() + "");
          check("kupyna384", x(digest(new DSTU7564Digest(384), m)).equals(f[4]), f[1].length() + "");
          check("kupyna512", x(digest(new DSTU7564Digest(512), m)).equals(f[5]), f[1].length() + "");
          break;
        }
        case "C": {
          GOST28147Engine e = new GOST28147Engine(); byte[] ct = new byte[8];
          e.init(true, new ParametersWithSBox(new KeyParameter(h(f[1])), sbox())); e.processBlock(h(f[2]), 0, ct, 0);
          check("gost28147", x(ct).equals(f[3]), line);
          break;
        }
        case "K": {
          byte[] key = h(f[1]), pt = h(f[2]), ct = h(f[3]), res = new byte[pt.length];
          String name = "kalyna" + pt.length * 8 + "/" + key.length * 8;
          DSTU7624Engine e = new DSTU7624Engine(pt.length * 8);
          e.init(true, new KeyParameter(key)); e.processBlock(pt, 0, res, 0);
          check(name, Arrays.equals(res, ct), line);
          e.init(false, new KeyParameter(key)); e.processBlock(ct, 0, res, 0);
          check(name + " decrypt", Arrays.equals(res, pt), line);
          break;
        }
        case "S": {
          ECDomainParameters p = DSTU4145NamedCurves.getByOID(new ASN1ObjectIdentifier("1.2.804.2.1.1.1.1.3.1.1.2." + f[1]));
          BigInteger d = new BigInteger(1, h(f[3]));
          ECPoint q = p.getG().multiply(d).negate().normalize();
          check("dstu4145 public key from d", x(DSTU4145PointEncoder.encodePoint(q)).equals(f[4]), "curve " + f[1] + " #" + f[2]);
          ECPoint dq = DSTU4145PointEncoder.decodePoint(p.getCurve(), h(f[4])).normalize();
          check("dstu4145 decode Go key", dq.equals(q), "curve " + f[1] + " #" + f[2]);
          byte[] hash = h(f[5]);
          DSTU4145Signer v = new DSTU4145Signer();
          v.init(false, new ECPublicKeyParameters(dq, p));
          check("dstu4145 verify Go signature", v.verifySignature(hash, new BigInteger(f[6], 16), new BigInteger(f[7], 16)), "curve " + f[1] + " #" + f[2]);
          DSTU4145Signer s = new DSTU4145Signer();
          s.init(true, new ParametersWithRandom(new ECPrivateKeyParameters(d, p), rnd));
          BigInteger[] rs = s.generateSignature(hash);
          out.println("X bc " + f[1] + " " + f[4] + " " + f[5] + " " + rs[0].toString(16) + " " + rs[1].toString(16));
          break;
        }
      }
    }
    out.close();
    for (Map.Entry<String,int[]> e : stats.entrySet())
      System.out.printf("BC 1.86  %-32s %4d ok %d mismatch%n", e.getKey(), e.getValue()[0], e.getValue()[1]);
    if (stats.values().stream().anyMatch(c -> c[1] > 0)) System.exit(1);
  }
}
