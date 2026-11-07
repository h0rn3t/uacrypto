import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.util.encoders.Hex;

// Cross-checks CRLs with Bouncy Castle 1.86 through its JCA provider. Each line
//   L <curve> <CA d> <CA cert> <CRL> <number> <base number or -> <entries>
// of uacrypto is verified by X509CRL.verify and read back; Bouncy Castle then
// issues the same CRL with the same key (V2TBSCertListGenerator, Signature
// GOST3411WITHDSTU4145LE) and writes
//   B <curve> <CA cert> <CRL> <number> <base number or -> <entries>
// for uacrypto to parse. entries: serial(hex):reason:Unix time,..., or -.
public class CRL {
  static Map<String,int[]> stats = new TreeMap<>();
  static void check(String what, boolean ok, String detail) {
    int[] c = stats.computeIfAbsent(what, k -> new int[2]); c[ok ? 0 : 1]++;
    if (!ok) System.err.println("MISMATCH " + what + " " + detail);
  }

  static boolean verifies(X509CRL crl, PublicKey key) {
    try { crl.verify(key, "BC"); return true; } catch (GeneralSecurityException e) { return false; }
  }

  static String extensionInteger(Extensions exts, ASN1ObjectIdentifier oid) {
    Extension e = exts == null ? null : exts.getExtension(oid);
    return e == null ? "-" : ASN1Integer.getInstance(e.getParsedValue()).getValue().toString();
  }

  static String entries(CertificateList list) {
    StringJoiner out = new StringJoiner(",");
    for (Enumeration<?> en = list.getRevokedCertificateEnumeration(); en.hasMoreElements(); ) {
      TBSCertList.CRLEntry e = (TBSCertList.CRLEntry) en.nextElement();
      int reason = 0;
      Extensions exts = e.getExtensions();
      if (exts != null && exts.getExtension(Extension.reasonCode) != null)
        reason = CRLReason.getInstance(exts.getExtension(Extension.reasonCode).getParsedValue()).getValue().intValue();
      out.add(e.getUserCertificate().getValue().toString(16) + ":" + reason + ":" + e.getRevocationDate().getDate().getTime() / 1000);
    }
    return out.length() == 0 ? "-" : out.toString();
  }

  public static void main(String[] a) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
    BufferedReader in = new BufferedReader(new FileReader(a[0]));
    PrintWriter out = new PrintWriter(new FileWriter(a[1]));
    for (String line; (line = in.readLine()) != null; ) {
      String[] f = line.split(" ");
      String what = "curve " + f[1] + " CRL " + f[5];
      byte[] certDER = Hex.decode(f[3]), crlDER = Hex.decode(f[4]);
      X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDER));
      X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlDER));
      check("verify uacrypto CRL", verifies(crl, cert.getPublicKey()), what);
      byte[] tampered = crlDER.clone();
      tampered[tampered.length - 1] ^= 1;
      check("reject tampered uacrypto CRL", !verifies((X509CRL) cf.generateCRL(new ByteArrayInputStream(tampered)), cert.getPublicKey()), what);
      CertificateList list = CertificateList.getInstance(crlDER);
      Extensions exts = list.getTBSCertList().getExtensions();
      check("uacrypto CRL number", extensionInteger(exts, Extension.cRLNumber).equals(f[5]), what);
      check("uacrypto delta CRL indicator", extensionInteger(exts, Extension.deltaCRLIndicator).equals(f[6]), what);
      check("uacrypto CRL entries", entries(list).equals(f[7]), what + ": " + entries(list) + " want " + f[7]);
      check("uacrypto CRL issuer", crl.getIssuerX500Principal().equals(cert.getSubjectX500Principal()), what);

      // The same CRL from Bouncy Castle, signed with the same key.
      V2TBSCertListGenerator gen = new V2TBSCertListGenerator();
      gen.setSignature(new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145le));
      gen.setIssuer(X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()));
      gen.setThisUpdate(list.getThisUpdate());
      gen.setNextUpdate(list.getNextUpdate());
      if (!f[7].equals("-"))
        for (String e : f[7].split(",")) {
          String[] p = e.split(":");
          gen.addCRLEntry(new ASN1Integer(new BigInteger(p[0], 16)), new Time(new Date(Long.parseLong(p[2]) * 1000)), Integer.parseInt(p[1]));
        }
      ExtensionsGenerator eg = new ExtensionsGenerator();
      eg.addExtension(Extension.authorityKeyIdentifier, false,
          new AuthorityKeyIdentifier(ASN1OctetString.getInstance(ASN1OctetString.getInstance(cert.getExtensionValue("2.5.29.14")).getOctets()).getOctets()));
      eg.addExtension(Extension.cRLNumber, false, new ASN1Integer(new BigInteger(f[5])));
      if (!f[6].equals("-")) eg.addExtension(Extension.deltaCRLIndicator, true, new ASN1Integer(new BigInteger(f[6])));
      gen.setExtensions(eg.generate());
      TBSCertList tbs = gen.generateTBSCertList();

      ECDomainParameters p = DSTU4145NamedCurves.getByOID(new ASN1ObjectIdentifier("1.2.804.2.1.1.1.1.3.1.1.2." + f[1]));
      ECParameterSpec spec = new ECParameterSpec(p.getCurve(), p.getG(), p.getN(), p.getH());
      PrivateKey key = KeyFactory.getInstance("DSTU4145", "BC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, Hex.decode(f[2])), spec));
      Signature s = Signature.getInstance("GOST3411WITHDSTU4145LE", "BC");
      s.initSign(key);
      s.update(tbs.getEncoded(ASN1Encoding.DER));
      byte[] bcCRL = new DERSequence(new ASN1Encodable[] {
          tbs, new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145le), new DERBitString(s.sign())}).getEncoded(ASN1Encoding.DER);
      check("verify own CRL", verifies((X509CRL) cf.generateCRL(new ByteArrayInputStream(bcCRL)), cert.getPublicKey()), what);
      out.println("B " + f[1] + " " + f[3] + " " + Hex.toHexString(bcCRL) + " " + f[5] + " " + f[6] + " " + f[7]);
    }
    out.close();
    for (Map.Entry<String,int[]> e : stats.entrySet())
      System.out.printf("BC 1.86  %-32s %4d ok %d mismatch%n", e.getKey(), e.getValue()[0], e.getValue()[1]);
    if (stats.values().stream().anyMatch(c -> c[1] > 0)) System.exit(1);
  }
}
