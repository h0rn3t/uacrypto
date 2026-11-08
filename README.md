# uacrypto

[![Go Reference](https://pkg.go.dev/badge/github.com/h0rn3t/uacrypto.svg)](https://pkg.go.dev/github.com/h0rn3t/uacrypto)
[![test](https://github.com/h0rn3t/uacrypto/actions/workflows/test.yml/badge.svg)](https://github.com/h0rn3t/uacrypto/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/h0rn3t/uacrypto/graph/badge.svg)](https://app.codecov.io/gh/h0rn3t/uacrypto)
![Go](https://img.shields.io/badge/go-1.27-00ADD8)
![License](https://img.shields.io/badge/license-MIT-green)

Українські криптографічні стандарти на чистому Go: ДСТУ 4145-2002, ГОСТ 34.311-95,
ДСТУ 7564:2014 «Купина», ДСТУ 7624:2014 «Калина», ДСТУ 8845:2019 «Струмок» та ГОСТ 28147-89.

- **Без залежностей** — лише стандартна бібліотека Go.
- **Сумісність байт у байт** з бібліотекою ІІТ «Користувач ЦСК» (EU Sign) і сертифікованими cryptonite
  та UAPKI: ті самі геші, те саме кодування ключів, підписи перевіряються в обидва боки.
- **Звичні інтерфейси Go** — `hash.Hash`, `cipher.Block`, `io.Reader` для випадковості.

## Пакети

| Пакет | Стандарт | Що вміє |
|---|---|---|
| [`dstu4145`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/dstu4145) | ДСТУ 4145-2002 — цифровий підпис на еліптичних кривих | усі 10 іменованих кривих (зокрема M257), генерація ключів, підпис, перевірка, стиснене кодування відкритого ключа, підпис `r‖s` у форматі ІІТ, узгодження ключів DH з кофактором (`ECDH`) |
| [`gost34311`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/gost34311) | ГОСТ 34.311-95 — функція гешування | `hash.Hash`, ДКЕ №1 за замовчуванням або власний S-блок; відтворює контрольні приклади стандарту; порожнє повідомлення гешується з нульовим блоком доповнення, як у cryptonite й UAPKI; HMAC — `crypto/hmac` над `New` |
| [`kupyna`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/kupyna) | ДСТУ 7564:2014 «Купина» — функція гешування | `hash.Hash` на 256, 384 і 512 біт; MAC з ключем (`NewMAC`) |
| [`kalyna`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/kalyna) | ДСТУ 7624:2014 «Калина» — блоковий шифр | `cipher.Block` з блоком 128, 256 і 512 біт; режими CTR, CFB, OFB, CBC, CMAC, GMAC, GCM, CCM, XTS і обгортання ключів — усі приклади стандарту, з неповними блоками |
| [`strumok`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/strumok) | ДСТУ 8845:2019 «Струмок» — потоковий шифр | `cipher.Stream` з ключем 256 і 512 біт; відтворює контрольні приклади стандарту |
| [`pki`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/pki) | X.509 і CMS з ДСТУ 4145 | ключ ДСТУ 4145 із сертифіката (явні параметри чи OID кривої, ДКЕ, le/be), РНОКПП і ЄДРПОУ власника, перевірка підпису сертифіката (ГОСТ 34.311, Купина-256, Купина-512), створення й перевірка CMS SignedData: файлів `.p7s` (CAdES-BES, CAdES-T і CAdES-X Long), створення XAdES-B-B, B-T, B-LT і B-LTA (вбудованих і відокремлених) і перевірка XAdES (B-B, B-T, B-LT, B-LTA), контейнерів ASiC-S і ASiC-E з CAdES і XAdES, створення й перевірка PAdES у PDF, позначок часу RFC 3161, клієнт TSP, клієнт OCSP і перевірка відповідей OCSP, перевірка CRL і статусу за повним і дельта-CRL; для ЦСК — випуск сертифікатів з іменами й розширеннями, як у ЦСК, PKCS#10, ключі PKCS#8 у форматах BC та ІІТ, ключові файли PKCS#12 і PKCS#8 з паролем (ГОСТ 28147, як у ІІТ), читання Key-6.dat ІІТ і JKS ПриватБанку, конверти CMS EnvelopedData, відповіді OCSP, CRL і позначки часу, пакети `.p7b` |
| [`gost28147`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/gost28147) | ГОСТ 28147-89 — блоковий шифр | `cipher.Block`, гамування (`NewCTR`), гамування зі зворотним зв'язком (`cipher.NewCFBEncrypter`), імітовставка (`NewMAC`); ДКЕ №1 з додатків 1–10 до інструкції №114, тестова таблиця ГОСТ 34.311, розпакування й пакування ДКЕ |
| [`gost3410`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/gost3410) | ГОСТ Р 34.10-2001 / ГОСТ 34.310-2004 — цифровий підпис на еліптичних кривих (перенесено з cryptonite) | генерація ключів, підпис, перевірка, стиснений відкритий ключ; параметри кривої задає викликач (`NewCurve`), бо українського набору немає; не ГОСТ 34.310-95 |

## Встановлення

```sh
go get github.com/h0rn3t/uacrypto@latest
```

Потрібен Go 1.27 або новіший.

## Приклади

### Підпис і перевірка (ДСТУ 4145 + ГОСТ 34.311)

```go
package main

import (
	"crypto/rand"
	"fmt"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost34311"
)

func main() {
	curve, _ := dstu4145.NamedCurve(dstu4145.M257) // крива кваліфікованих сертифікатів; кореневі — M431
	key, _ := dstu4145.GenerateKey(curve, rand.Reader)

	digest := gost34311.Sum([]byte("документ"))
	r, s, _ := dstu4145.Sign(rand.Reader, key, digest[:])

	fmt.Println(dstu4145.Verify(key.Public(), digest[:], r, s)) // true
}
```

### Відкритий ключ із сертифіката

Відкритий ключ ДСТУ 4145 у сертифікаті — це стиснена точка, вміст OCTET STRING у
`subjectPublicKey`. Якщо OID алгоритму `dstu4145le` (`1.2.804.2.1.1.1.1.3.1.1`), байти
записані у зворотному порядку:

```go
point := slices.Clone(octets)
slices.Reverse(point) // лише для dstu4145le; для dstu4145be — як є
pub, err := dstu4145.ParsePublicKey(curve, point)
```

`ParsePublicKey` перевіряє, що точка лежить на кривій і належить підгрупі порядку n.

### Підпис у форматі ІІТ

`Sign` повертає `r` і `s` як числа. У сертифікатах, OCSP і CMS українські ЦСК
записують підпис як `r‖s`, кожне число в little-endian довжиною порядку кривої
(для M257 — по 32 байти, як у test-ca та ІІТ):

```go
sig := dstu4145.MarshalSignature(curve, r, s) // 64 байти на M257

r, s, err := dstu4145.ParseSignature(sig)
ok := dstu4145.Verify(pub, digest[:], r, s)
```

`ParseSignature` ділить будь-який непорожній підпис парної довжини навпіл, тож читає й підписи
JCA-провайдера Bouncy Castle, де половина може мати зайвий нульовий байт.

### Перевірка сертифіката

`crypto/x509` розбирає українські сертифікати, але ключ і підпис ДСТУ 4145 лишає невідомими.
Пакет `pki` додає саме цю частину:

```go
cert, err := x509.ParseCertificate(der)
issuer, err := x509.ParseCertificate(issuerDER)
err = pki.CheckCertificateSignature(cert, issuer) // nil, pki.ErrInvalidSignature або x509.ErrUnsupportedAlgorithm

key, err := pki.ParsePublicKey(cert.RawSubjectPublicKeyInfo) // *dstu4145.PublicKey і ДКЕ з параметрів
alg, err := pki.CertificateSignatureAlgorithm(cert)          // OID підпису: crypto/x509 для ДСТУ його не знає

codes, err := pki.ParseSubjectAttributes(cert) // codes.DRFO — РНОКПП, codes.EDRPOU — ЄДРПОУ
```

РНОКПП і код ЄДРПОУ українські ЦСК пишуть у розширенні `subjectDirectoryAttributes`
(OID `1.2.804.2.1.1.1.11.1.4.1.1` і `…4.2.1`); порожнє поле означає, що коду в сертифікаті немає.

Перевіряється лише підпис. Строк дії, призначення ключа й імена перевіряйте засобами `crypto/x509`.

### Перевірка підписаного файла (CMS, `.p7s`)

```go
content, signers, err := pki.VerifySignedData(p7s, nil, nil)      // вміст усередині підпису
// signers[i].Certificate, .SigningTime (заява підписувача), .TimeStamp (перевірена позначка CAdES-T)
_, signers, err = pki.VerifySignedData(p7s, document, nil)         // відокремлений підпис
_, signers, err = pki.VerifySignedData(p7s, nil, []*x509.Certificate{signerCert}) // сертифіката немає в підписі
_, signers, err = pki.VerifySignedData(p7s, nil, czoBundle)       // сертифікати з CACertificates.p7b ЦЗО
```

ІІТ не кладе в CAdES-T і CAdES-X Long сертифікати TSA й OCSP-сервера: перевіряльник бере їх із пакета
сертифікатів ЦСК. Тому для таких підписів передайте в `certs` сертифікати з
[CACertificates.p7b](https://czo.gov.ua/download/certificates/CACertificates.p7b); сертифікати шукаються
в підписі, у токені позначки часу чи відповіді OCSP, в атрибуті `certValues`, а потім у `certs`.

Перевіряються всі підписувачі: атрибути `contentType` і `messageDigest`, потім підпис ДСТУ 4145.
Підпис приймається і в записі ІІТ (`r‖s` як є), і в записі Bouncy Castle (`r‖s` у вкладеному
OCTET STRING). Позначка часу RFC 3161 — теж CMS SignedData, її перевіряє та сама функція.
Підпис приймається в DER і в BER, який пишуть потокові засоби (невизначені довжини, вміст шматками);
довіру до сертифікатів підписувачів перевіряйте окремо.

### Підпис файла (CMS, CAdES-BES)

```go
p7s, err := pki.SignData(rand.Reader, document, key, cert, pki.SignOptions{Detached: true})
```

Підпис має ту форму, яку пишуть українські кваліфіковані засоби: атрибути `contentType`,
`signingTime`, `messageDigest`, `signingCertificateV2`, геш Купина-256 (або ГОСТ 34.311 з
`GOST34311: true`), підписувач — за видавцем і серійним номером, значення підпису `r‖s` little-endian.

### Позначка часу (TSP, CAdES-T)

```go
tsa := &pki.TSAClient{URL: "http://ca.diia.gov.ua/services/tsp/"}
cadesT, err := pki.AddSignatureTimeStamp(ctx, p7s, tsa) // позначка на значенні підпису кожного підписувача

token, ts, err := tsa.TimeStamp(ctx, data) // окрема позначка часу для даних
ts, err = pki.VerifyTimeStamp(token, data)
fmt.Println(ts.Time, ts.Certificate.Subject.CommonName)
```

Клієнт надсилає запит із nonce і геш Купина-256 (або ГОСТ 34.311 з `GOST34311: true`) і приймає
лише токен, який перевіряється: підпис ДСТУ 4145, сертифікат TSA з призначенням timeStamping,
геш даних і повернений nonce. Для CAdES-T геш береться той самий, що й у підписувача.

### Дані для довготривалої перевірки (CAdES-X Long)

```go
// cadesT — результат AddSignatureTimeStamp; caCerts — сертифікати ЦСК і кореневий сертифікат ЦЗО
long, err := pki.AddValidationData(ctx, cadesT, caCerts, &pki.OCSPClient{})

_, signers, err := pki.VerifySignedData(long, nil, czoBundle)
// signers[i].Chain — шлях від підписувача до кореня, signers[i].OCSP[j] — перевірена відповідь про Chain[j]
// або nil, якщо в підписі її немає
```

Українські засоби пишуть дані для довготривалої перевірки у форматі CAdES-X Long (RFC 5126), а не
CAdES-B-LT з EN 319 122: так їх називають і [тестові приклади ЦЗО](https://czo.gov.ua/testexamples)
за наказом Мінцифри № Н 191 (CAdES-BES, CAdES-T, CAdES-C, CAdES-X Long). Усе лежить у непідписаних
атрибутах `completeCertificateRefs`, `completeRevocationRefs`, `certValues` і `revocationValues`, поле
`crls` у SignedData порожнє. ІІТ пише дві форми:

| ІІТ | Відповіді OCSP | Сертифікати TSA й OCSP-серверів |
|---|---|---|
| «з повними даними для перевірки» | лише про сертифікат підписувача | немає, беруться з пакета ЦСК |
| «з повними даними ЦСК для перевірки» | про підписувача й про ЦСК | у токені й відповідях |

`AddValidationData` пише другу, повнішу форму: будує шлях до самопідписаного кореня з сертифікатів
підпису й `caCerts`, питає про кожен сертифікат шляху, крім кореня, OCSP-сервер, названий у ньому, і
кладе в `certValues` і `completeCertificateRefs` (з `issuerSerial`) сертифікати ЦСК шляху, а в
`completeRevocationRefs` — по посиланню на кожен сертифікат шляху, кореневе порожнє. Посилання
гешуються алгоритмом підписувача. Потрібен CAdES-T; відкликаний чи невідомий сертифікат — помилка.

`VerifySignedData` читає обидві форми: звіряє посилання зі значеннями, будує шлях і перевіряє кожну
наявну відповідь OCSP, а статуси й час відповідей лишає на ваш розсуд; довіру до кореня перевіряйте
окремо. Обидві форми перевірено на тестових прикладах ЦЗО (`pki/testdata/czo-test-*`).

### Контейнери ASiC (`.asics`, `.asice`)

```go
sign := func(data []byte) ([]byte, error) { // відокремлений CAdES; можна додати позначку часу й дані перевірки
	return pki.SignData(rand.Reader, data, key, cert, pki.SignOptions{Detached: true})
}
asics, err := pki.CreateASiCS(pki.ASiCFile{Name: "звіт.pdf", Data: pdf}, sign)
asice, err := pki.CreateASiCE([]pki.ASiCFile{{Name: "a.pdf", Data: a}, {Name: "b.xml", Data: b}}, false, sign)

files, signers, err := pki.VerifyASiC(asice, certs) // лише файли, які покриває підпис
```

Контейнери — як у ІІТ (ETSI EN 319 162-1): ASiC-S підписує сам файл (`META-INF/signature.p7s`), ASiC-E —
маніфест `META-INF/ASiCManifest001.xml` з гешами файлів (Купина-256 або ГОСТ 34.311, URI
`…xmlenc#dstu7564-256` і `…xmlenc#gost34311`, як пише ІІТ). Маніфест для того самого файла збігається з
маніфестом ІІТ байт у байт; контейнери ЦЗО з CAdES-BES, T і X Long перевіряються. Файл, якого не покриває
жоден підпис, `VerifyASiC` не повертає; змінений файл — `ErrInvalidSignature`. Контейнери з XAdES
(`META-INF/signatures*.xml`) `VerifyASiC` перевіряє як `VerifyXAdES`.

```go
signXAdES := func(files []pki.ASiCFile) ([]byte, error) { // відокремлений XAdES; можна додати B-T і B-LT
	sig, err := pki.SignXAdESDetached(rand.Reader, files, key, cert, pki.SignOptions{})
	if err != nil {
		return nil, err
	}
	return pki.AddXAdESSignatureTimeStamp(ctx, sig, tsa)
}
asics, err := pki.CreateASiCSXAdES(pki.ASiCFile{Name: "звіт.pdf", Data: pdf}, signXAdES)
asice, err := pki.CreateASiCEXAdES([]pki.ASiCFile{{Name: "a.pdf", Data: a}, {Name: "b.xml", Data: b}}, signXAdES)
```

`CreateASiCSXAdES` і `CreateASiCEXAdES` кладуть підпис у `META-INF/signatures.xml` (ASiC-S) чи
`META-INF/signatures001.xml` (ASiC-E) з коренем `asic:XAdESSignatures`; ASiC-E ще має маніфест OpenDocument
`META-INF/manifest.xml`. Склад і порядок записів, маніфест (байт у байт) і розмітка підпису збігаються з
контейнерами ЦЗО `DSTU/XAdES-B-B` (ASiC-S) і `DSTU-7564/XAdES-B-T` (ASiC-E).

### Підписи XAdES

```go
doc, err := pki.SignXAdES(rand.Reader, doc, key, cert, pki.SignOptions{}) // підпис усередині документа
sig, err := pki.SignXAdESDetached(rand.Reader, []pki.ASiCFile{{Name: "Test.xml", Data: data}}, key, cert, pki.SignOptions{})
doc, err = pki.AddXAdESSignatureTimeStamp(ctx, doc, tsa) // B-T
doc, err = pki.AddXAdESValidationData(ctx, doc, certs, &pki.OCSPClient{}) // B-LT
doc, err = pki.AddXAdESArchiveTimeStamp(ctx, doc, nil, tsa) // B-LTA; для відокремленого — файли за URI
signed, signers, err := pki.VerifyXAdES(doc, nil, certs) // вбудований підпис: signed == [""]
signed, signers, err = pki.VerifyXAdES(sig, map[string][]byte{"Test.xml": data}, certs) // відокремлений
```

`VerifyXAdES` перевіряє підписи XAdES, як їх пише ІІТ: канонікалізація Exclusive XML C14N, ДСТУ 4145 з
ГОСТ 34.311 або Купиною-256, сертифікат підписувача — за `SigningCertificateV2`. Позначку часу
`SignatureTimeStamp` (B-T) перевіряє над канонічним `ds:SignatureValue`. З `CertificateValues` і
`RevocationValues` (B-LT) будує `Signer.Chain` і `Signer.OCSP`, як для CAdES-X Long. Кожну
`ArchiveTimeStamp` (B-LTA) перевіряє над входом ETSI EN 319 132-1, 5.5.2.2 (дані посилань, канонічні
`ds:SignedInfo`, `ds:SignatureValue`, `ds:KeyInfo`, непідписані властивості перед нею й `ds:Object`, крім
того, що з `QualifyingProperties`) і віддає в `Signer.ArchiveTimeStamps`. Документи з DOCTYPE і з повторним `Id` відхиляються, інші перетворення —
`errors.ErrUnsupported`. Перевірено на зразках ЦЗО (B-B, B-T, B-LT, B-LTA; вбудовані, відокремлені й у
ASiC) і на прикладах рекомендацій W3C щодо канонікалізації.

`SignXAdES` дописує XAdES-B-B останнім дочірнім елементом кореня документа, `SignXAdESDetached` повертає
відокремлений підпис файлів; розмітка — як у ІІТ (без змінних значень збігається зі зразками ЦЗО байт у байт).
`AddXAdESSignatureTimeStamp` робить з B-B підпис B-T: просить TSA позначити канонічний `ds:SignatureValue`
(геш — алгоритм підпису) і дописує `UnsignedProperties` із `SignatureTimeStamp`. `AddXAdESValidationData`
робить з B-T підпис B-LT: будує шлях до кореня з `certs`, питає OCSP про сертифікат підписувача і дописує
`CertificateValues` (ЦСК, корінь і сертифікат OCSP-сервера, якщо це не ЦСК) та `RevocationValues` з
відповіддю — як у зразку ЦЗО, без відповідей про ЦСК. Відкликаний чи невідомий сертифікат — помилка.
`AddXAdESArchiveTimeStamp` робить з B-LT підпис B-LTA: просить TSA позначити той самий вхід, що перевіряє
`VerifyXAdES` (геш — алгоритм підпису, як у ІІТ), і дописує `xadesv141:ArchiveTimeStamp` останньою
непідписаною властивістю; повторний виклик додає ще одну позначку, яка покриває попередні. Відокремленому
підпису потрібні файли, їхні геші звіряються з посиланнями. Розмітка B-T, B-LT і B-LTA без змінних значень
збігається зі зразками ЦЗО байт у байт.

### Підписи PAdES

```go
signed, err := pki.SignPAdES(ctx, rand.Reader, pdf, key, cert, pki.SignOptions{}, nil) // B-B; з tsa — B-T
signed, err = pki.AddPAdESValidationData(ctx, signed, certs, &pki.OCSPClient{})         // B-LT: /DSS
signed, err = pki.AddPAdESDocumentTimeStamp(ctx, signed, tsa)                           // B-LTA
sigs, err := pki.VerifyPAdES(signed, certs) // кожен підпис і позначка часу документа
```

`VerifyPAdES` перевіряє підписи PDF (ETSI EN 319 142), як їх пише ІІТ: CAdES з `/SubFilter`
`ETSI.CAdES.detached` чи `adbe.pkcs7.detached` над `/ByteRange` — як `VerifySignedData`, позначку часу
документа `ETSI.RFC3161` (B-LTA) — як `VerifyTimeStamp`. `/ByteRange` має починатися з нуля й оминати рівно
`/Contents` свого підпису; `CoversDocument` каже, чи підпис покриває файл до кінця, без пізніших оновлень.
Сертифікати й відповіді OCSP зі сховища `/DSS` (і його `/VRI`) будують `Signer.Chain` і `Signer.OCSP`, як для
CAdES-X Long; CRL з DSS не читаються. Час підпису — `/M`: PAdES не має атрибута `signingTime`. Перевірено на
зразках ЦЗО (B-B, B-T, B-LT, B-LTA, ГОСТ 34.311 і Купина-256). `SignPAdES` дописує інкрементне оновлення, як
ІІТ: поле підпису в `/AcroForm` з `/SigFlags 3` і CAdES без `signingTime` у `/Contents` на 10240 байтів.
`AddPAdESValidationData` дописує сховище `/DSS` (`/Certs` і `/OCSPs` без `/VRI`), як ІІТ з «повними даними
ЦСК»: шляхи ЦСК підписувача й TSA його позначки часу, сертифікати OCSP-серверів і відповіді OCSP про кожен
сертифікат цих шляхів, крім коренів (на зразку ЦЗО — ті самі 5 сертифікатів і 3 відповіді). Підпис без
позначки часу, відкликаний сертифікат чи документ, що вже має DSS, — помилка. `AddPAdESDocumentTimeStamp`
дописує позначку часу документа (`/Type /DocTimeStamp`, `/SubFilter /ETSI.RFC3161`); на відміну від ІІТ пише
`/Filter /Adobe.PPKLite`, якого вимагає ISO 32000-1.
Читаються PDF з класичними таблицями перехресних посилань, з потоками перехресних посилань (PDF 1.5+) і гібридні
(`/XRefStm`, як пише Word), об'єкти в потоках об'єктів, `FlateDecode` з предикторами PNG. Оновлення пише потік
перехресних посилань, якщо ним закінчується документ, інакше — таблицю. Зашифровані PDF — `errors.ErrUnsupported`.

### Статус сертифіката (OCSP)

```go
ocsp := &pki.OCSPClient{} // адреса — з сертифіката; URL задає іншу
resp, err := ocsp.Check(ctx, cert, issuer)
switch resp.Status {
case pki.OCSPGood:
case pki.OCSPRevoked:
	fmt.Println(resp.RevokedAt, resp.RevocationReason)
case pki.OCSPUnknown:
}

resp, err = pki.ParseOCSPResponse(der, cert.SerialNumber, issuer) // збережена відповідь
```

Клієнт надсилає запит із nonce і CertID на Купині-256 (або ГОСТ 34.311 з `GOST34311: true`)
і приймає лише відповідь, яка перевіряється: підпис ДСТУ 4145, відповідач — сам видавець або
сертифікат, який видавець видав для OCSP-підписування й чинний на момент відповіді, статус саме
цього сертифіката й повернений nonce. Відповідача шукають за іменем або за KeyHash, що дорівнює
SubjectKeyId (так пише monobank). `ParseOCSPResponse` не перевіряє свіжість — порівняйте
`ThisUpdate` і `NextUpdate` з потрібним часом; `resp.Raw` — уся відповідь для зберігання.

### Статус сертифіката (CRL)

```go
full, err := pki.ParseRevocationList(fullDER, issuer)   // підпис ДСТУ 4145, ім'я, AKI і cRLSign видавця
delta, err := pki.ParseRevocationList(deltaDER, issuer) // дельта-CRL, як у ЦЗО й КНЕДП; може бути nil
entry, revoked, err := pki.RevocationStatus(cert.SerialNumber, full, delta)
if revoked {
	fmt.Println(entry.RevocationTime, entry.ReasonCode) // 6 — certificateHold: призупинено
}
```

Список розбирає `crypto/x509` (`*x509.RevocationList`); `ParseRevocationList` перевіряє, що його підписав
саме цей ключ видавця. `RevocationStatus` бере дельта-CRL понад повним: запис дельти важливіший, а
`removeFromCRL` у ній знімає призупинення; дельта має стосуватися того самого ключа видавця й повного CRL
не новішого за нього. Свіжість (`ThisUpdate`, `NextUpdate`) не перевіряється, як і в OCSP. Перевірено на
повних і дельта-CRL ЦЗО: статус відкликаного сертифіката збігається з відповіддю OCSP ЦЗО.

### ЦСК: сертифікати, заявки, OCSP і TSP

Те, що потрібно тестовому ЦСК (на цьому API працює test-ca DATAHUB, сумісний із ca.java на Bouncy Castle):

```go
// ключ і самопідписаний корінь; шаблон — звичайний x509.Certificate,
// політика 1.2.804.2.1.1.1.2.2 ставиться типово, як у всіх сертифікатах ЦСК
key, _ := dstu4145.GenerateKey(curve, rand.Reader)
spki, _ := pki.MarshalPublicKey(&pki.PublicKey{Key: key.Public(), DKE: gost28147.DKE1()})
// ім'я як у ЦСК: O, OU, CN, serialNumber, C, L; serialNumber і C — PrintableString, решта — UTF8String
tmpl.RawSubject, _ = pki.MarshalName(pkix.Name{Organization: []string{"Тестова організація"}, CommonName: "Тестовий ЦСК",
	SerialNumber: "UA-00000000-2026", Country: []string{"UA"}, Locality: []string{"Київ"}})
rootDER, _ := pki.CreateCertificate(rand.Reader, tmpl, tmpl, spki, key)
pkcs8, _ := pki.MarshalPKCS8PrivateKey(key) // як пише BC; pki.ParsePKCS8PrivateKey читає назад

// заявка PKCS#10 (DER або BER): ключ іншого алгоритму розбирається з PublicKey == nil
req, _ := pki.ParseCertificateRequest(p10)
err := req.CheckSignature() // володіння ключем; pki.ErrInvalidSignature або x509.ErrUnsupportedAlgorithm
codes, _ := pki.MarshalSubjectAttributes(pki.SubjectAttributes{DRFO: "1234567890", EDRPOU: "12345678"})
sia, _ := pki.MarshalSubjectInfoAccess("http://ca.example/services/tsp/") // адреса TSA (id-ad-timeStamping)
userTmpl.ExtraExtensions = append(userTmpl.ExtraExtensions, sia, codes) // codes — як ЦСК пишуть РНОКПП і ЄДРПОУ
userKey, _ := req.CertificatePublicKey() // LE-ключ (ІІТ) — як є, BE-ключ (BC) — у LE-формі
userDER, _ := pki.CreateCertificate(rand.Reader, userTmpl, root, userKey, key)

// як пишуть ЦСК на Bouncy Castle: AKI ще й з іменем і серійним номером видавця,
// а в сертифікаті OCSP-відповідача — критичне EKU OCSPSigning та id-pkix-ocsp-nocheck
aki, _ := pki.MarshalAuthorityKeyIdentifier(root)
ocspTmpl.ExtraExtensions = append([]pkix.Extension{aki}, pki.OCSPResponderExtensions()...)

// OCSP-відповідач
ocspReq, _ := pki.ParseOCSPRequest(body)
issued, _ := ocspReq.CertIDs[0].IssuedBy(root) // ГОСТ 34.311, Купина, SHA-1/2/3, MD5
tmpl := &pki.OCSPResponseTemplate{ProducedAt: now, Nonce: ocspReq.Nonce, Responses: ...} // nonce — назад без змін
resp, _ := pki.CreateOCSPResponse(rand.Reader, tmpl, responder, responderKey)

// TSA: політика, nonce, розширення й certReq — із запиту; невідомий геш — відмова badAlg;
// без політики в запиті й у TimeStamp — 1.2.804.2.1.1.1.2.3.1, як у TSA на ГОСТ 34.311
tsReq, _ := pki.ParseTimeStampRequest(body)
tsResp, _ := pki.CreateTimeStampResponse(rand.Reader, tsReq, &pki.TimeStamp{Time: time.Now(), SerialNumber: serial, Policy: policy, Certificate: tsa}, tsaKey)

// CRL: шаблон — x509.RevocationList; AKI — з SubjectKeyId видавця; дельта-CRL — з критичним
// Delta CRL Indicator (2.5.29.27, номер базового повного CRL) в ExtraExtensions
crlDER, _ := pki.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: number, ThisUpdate: now, NextUpdate: now.Add(7 * 24 * time.Hour),
	RevokedCertificateEntries: entries}, root, key)

// пакет сертифікатів, як CACertificates.p7b
certs, _ := pki.ParseCertificateBundle(p7b)
p7b, _ = pki.MarshalCertificateBundle(certs)
```

`CreateCertificate` бере поля шаблону з `crypto/x509` і підписує ДСТУ 4145 + ГОСТ 34.311 (`dstu4145le`).
Ключ власника йде в сертифікат як є: українські засоби пишуть явні параметри кривої і ДКЕ, і
перекодування їх змінило б. Типові значення — як у сертифікатах ЦЗО: SKI — ГОСТ 34.311 бітів ключа,
AKI самопідписаного — його SKI, розширене призначення лише timeStamping — критичне (RFC 3161).
`ExtraExtensions` замінюють побудовані розширення, як у `crypto/x509`: так test-ca пише AKI з іменем
і серійним номером видавця і критичне призначення OCSP-сервера. Заявки, запити OCSP і TSP приймаються
і в BER — Bouncy Castle теж їх приймає.

### Збереження приватного ключа

```go
d := key.Bytes()                               // big-endian, довжина порядку кривої
restored, err := dstu4145.NewPrivateKey(curve, d)

key.Destroy() // затирає скаляр d; далі Sign і ECDH повертають ErrKeyDestroyed
```

### Генератор ДСТУ (як у cryptonite)

Сертифікована бібліотека cryptonite генерує ключі й підписує лише з власним генератором
псевдовипадкових чисел (`PRNG_MODE_DSTU`): ГОСТ 28147-89 з ДКЕ №1 у режимі простої заміни,
у стан домішується зашифрований час засівання. `dstu4145.NewPRNG` — той самий генератор як
`io.Reader`, для тих, кому він потрібен замість `crypto/rand`:

```go
seed := make([]byte, dstu4145.SeedSize) // 40 байтів: ключ ГОСТ 28147 і початковий стан
rand.Read(seed)                         // або апаратне джерело випадковості
prng, _ := dstu4145.NewPRNG(seed)
prng.Seed(extra)                        // домішати ще випадковості, як prng_seed cryptonite

key, _ := dstu4145.GenerateKey(curve, prng)
r, s, _ := dstu4145.Sign(prng, key, digest[:])
```

Вихід збігається з cryptonite байт у байт за того самого сіда й часу: звірка
`make -C parity cryptonite` збирає C-код cryptonite з підставленим годинником. `PRNG` не безпечний для
одночасного використання з кількох горутин. `prng.Destroy()` затирає ключ і стан, після нього `Read` повертає
помилку.

### Ключові файли (PKCS#12, PKCS#8 з паролем, Key-6.dat, JKS)

```go
pfx, err := pki.DecodePFX(data, password)     // .pfx/.p12 від ІІТ чи cryptonite; pki.ErrIncorrectPassword
key, err := pfx.KeyFor(cert)                  // ключ, відкритий ключ якого засвідчує cert
data, err = pki.EncodePFX(rand.Reader, pfx, newPassword, 10000) // зміна пароля — decode і encode

pkcs8, err := pki.DecryptPKCS8PrivateKey(encrypted, password) // EncryptedPrivateKeyInfo, як у ІІТ і jkurwa
key, err = pki.ParsePKCS8PrivateKey(pkcs8)                     // і запис ІІТ: d little-endian
agreement, err := pki.ParsePKCS8KeyAgreementKey(pkcs8)         // ключ узгодження ІІТ з атрибутів

store, err := pki.DecodeIITKey6(data, password) // Key-6.dat від ІІТ: PBES2 або старе сховище ІІТ
store, err = pki.DecodeJKS(data, password)      // .jks від ПриватБанку: ключі й сертифікати сховища
```

Пароль захищає ключ так, як у ІІТ і cryptonite: PBES2, PBKDF2 на HMAC ГОСТ 34.311 і ГОСТ 28147-89 у
режимі CFB з ДКЕ №1; MAC контейнера — HMAC ГОСТ 34.311 з ключем за додатком B RFC 7292. Ключ ІІТ
у PKCS#8 — сам `d` little-endian, а не `ECPrivateKey`, як у Bouncy Castle; другий ключ, для
узгодження (конвертів), ІІТ кладе в атрибут `1.3.6.1.4.1.19398.1.1.2.3` з оберненим порядком бітів.
`EncodePFX` пише ключі в записі ІІТ: криву явними параметрами, як ІІТ (обидва ключі PFX ІІТ з тестів
cryptonite відтворюються байт у байт); кожен ключ і сертифікат ключа позначає `localKeyID` (SKI ключа), як ІІТ. Перевірено на PFX ІІТ
з тестів cryptonite і на ключі `STORE_A040` з тестів jkurwa (шифрування відтворюється байт у байт).

Key-6.dat ІІТ буває у двох видах: EncryptedPrivateKeyInfo з PBES2, як у `DecryptPKCS8PrivateKey`, і
старе сховище ІІТ (`1.3.6.1.4.1.19398.1.1.1.2`) — ГОСТ 28147-89 у режимі простої заміни з ДКЕ №1 на
ключі, який дає ГОСТ 34.311, застосований 10000 разів до пароля; його 4-байтове контрольне значення,
як і jkurwa, не перевіряємо. JKS — сховище Java, у якому ПриватБанк видає ключі ДСТУ 4145: пароль
(UTF-16BE) перевіряє дайджест сховища і знімає захист кожного ключа (SHA-1, OID
`1.3.6.1.4.1.42.2.17.1.1`); сертифікати повертаються в порядку сховища, разом з довіреними. Обидві
функції повертають `PFX` з ключем і ключем узгодження ІІТ, хибний пароль — `pki.ErrIncorrectPassword`.
Логіку перенесено з jkurwa, gost89 і jksreader; перевірено на сховищах, які записали jkurwa/gost89,
OpenJDK з ключем Bouncy Castle і ua-cryptography-pki (Rust) — справжніх файлів ІІТ і ПриватБанку серед
тестових даних немає.

### Конверти (CMS EnvelopedData)

```go
env, err := pki.EncryptEnvelopedData(rand.Reader, data, agreement, myCert, []*x509.Certificate{theirCert})
data, err = pki.DecryptEnvelopedData(env, agreement, myCert, []*x509.Certificate{senderCert})
```

Конверт — як у cryptonite, ІІТ і jkurwa: вміст шифрується ГОСТ 28147-89 у режимі CFB з ДКЕ сертифіката
відправника, ключ вмісту — для кожного одержувача окремо через `dhSinglePass-cofactorDH-gost34311kdf`
(DH з кофактором, KDF на ГОСТ 34.311) і `GOST28147Wrap` (наказ № 108, VI.1). Одержувачу на тій самій
кривій відправник пише свій сертифікат за видавцем і номером, тож для розкриття потрібен сертифікат
відправника; одержувачу на іншій кривій — ефемерний ключ у самому конверті. Розкриваються й конверти в
режимі гамування та потокові (BER). Конверт нікого не автентифікує: щоб знати відправника, конверт
підписують. Перевірено на конверті з тестів jkurwa (ключ, обгортання і вміст сходяться байт у байт) і
звіркою з jkurwa в обидва боки (`make envelope` у `parity`).

### Геші

```go
sum := gost34311.Sum(data)  // [32]byte, ДКЕ №1
k256 := kupyna.Sum256(data) // [32]byte
k512 := kupyna.Sum512(data) // [64]byte

h := kupyna.New384()        // потоково, як будь-який hash.Hash
io.Copy(h, file)
fmt.Printf("%x\n", h.Sum(nil))
```

### Шифрування «Калиною»

```go
block, err := kalyna.NewCipher256(key) // блок 32 байти, ключ 32 або 64 байти
gcm, err := kalyna.NewGCM(block, 16)   // тег 16 байтів
sealed, err := gcm.Seal(nonce, plaintext, nil)
opened, err := gcm.Open(nonce, sealed, nil)
```

`NewCipher128` бере ключ 16 або 32 байти, `NewCipher512` — 64 байти. `NewCTR`, `NewCFB`,
`CMAC`, `GMAC`, `NewGCM`, `NewCCM`, `NewXTS`, `Wrap` і `Unwrap` реалізують режими ДСТУ 7624 і
відтворюють усі 75 прикладів стандарту з тестів сертифікованої бібліотеки
[cryptonite](https://github.com/privat-it/cryptonite), зокрема неповні блоки (крадіжка шифротексту
в XTS, доповнення ключа в `Wrap`, `80 00…` у CMAC і CCM); CFB і CMAC збігаються з бібліотекою ІІТ на всіх
довжинах. OFB і CBC ДСТУ — це `cipher.NewOFB` і `cipher.NewCBCEncrypter` над блоком «Калини»;
CTR і CFB з `crypto/cipher` — інші схеми.

`NewGCM` рахує GCM за ДСТУ: нонс у тег не входить, тож тег перевіряється й з іншим нонсом,
а повідомлення без відкритого тексту має однаковий тег за будь-якого нонса. Для систем, що
обмінюються лише між собою, `NewGCMWithNonceAuth` автентифікує й нонс (як `NewGCM` з
`nonce || additionalData` в AAD). Нонс GCM і CCM має бути завдовжки рівно один блок. Повторний
нонс із тим самим ключем неприпустимий.

### Шифрування «Струмком»

```go
stream, err := strumok.NewCipher(key, iv) // ключ 32 або 64 байти, IV 32 байти
stream.XORKeyStream(ciphertext, plaintext) // той самий виклик розшифровує
```

Стандарт задає ключ, IV і гаму 64-бітними словами; `strumok` читає й пише кожне слово
little-endian, як реалізації на C. Гама відтворює всі вісім прикладів додатка D ДСТУ 8845:2019.
Чи так само впорядковує байти бібліотека ІІТ (сесії `EU_SESSION_ENC_ALGO_DSTU8845_*`), ще не
перевірено. Повторна пара ключ–IV неприпустима: шифр не автентифікує дані.

ГОСТ 34.311 з нестандартним ДКЕ, наприклад з параметрів ключа:

```go
sbox, err := gost28147.UnpackDKE(dke) // 64 байти
h, err := gost34311.NewWithSbox(sbox)
```

## Криві ДСТУ 4145-2002

Номер кривої — останній елемент OID `1.2.804.2.1.1.1.1.3.1.1.2.N`.

| N | Поле | N | Поле |
|---|---|---|---|
| 0 | GF(2¹⁶³) | 5 | GF(2²³³) |
| 1 | GF(2¹⁶⁷) | 6 | GF(2²⁵⁷), **M257** |
| 2 | GF(2¹⁷³) | 7 | GF(2³⁰⁷) |
| 3 | GF(2¹⁷⁹) | 8 | GF(2³⁶⁷) |
| 4 | GF(2¹⁹¹) | 9 | GF(2⁴³¹) |

## Як перевірено

**Модульні тести** (`go test -race ./...`):

- еталонні вектори для кожного алгоритму й кожної з 10 кривих: ключ, кодування точки, підпис, геші на
  входах від 0 до 1000 байтів (геш порожнього повідомлення — з тестів cryptonite і UAPKI);
- реальний підпис кореневого сертифіката тестового ЦСК, який приймає бібліотека ІІТ;
- реальні сертифікати ЗЦ НБУ, ЦЗО, ДКСУ, «Вчасно» і monobank: ГОСТ 34.311, Купина-256 і Купина-512, ключі le і be, крива явними параметрами;
- реальні позначки часу TSA ДПС, ПриватБанку і Дії (CMS з ГОСТ 34.311 і Купиною-256), зокрема зі зміненим вмістом і підписом;
- реальні відповіді OCSP ЦЗО (good і revoked, делегований відповідач за іменем, дві різні криві) і monobank (відповідач за KeyHash, Купина-512);
- контрольні приклади Купини-256 з ДСТУ 7564:2014, Калини-128/128 з ДСТУ 7624:2014 і «Струмка» з додатка D
  ДСТУ 8845:2019;
- фаз-тест розбору відкритого ключа.

**Покриття тестами** рахує CI на кожен пуш у `main` і кожен pull request, звіт —
на [Codecov](https://app.codecov.io/gh/h0rn3t/uacrypto). Утиліта звірки `parity/` не враховується.
На 2026-11-04 (v0.0.6) покрито 88,6 % інструкцій:

| Пакет | Покриття |
|---|--:|
| `kalyna`, `kupyna`, `internal/spn` | 100 % |
| `gost34311` | 98,9 % |
| `gost28147` | 95,0 % |
| `dstu4145` | 93,7 % |
| `pki` | 84,5 % |

**Звірка з іншими реалізаціями** ([`parity/`](parity), `cd parity && make`). Одні й ті самі
відтворювані випадкові дані рахують uacrypto та незалежні бібліотеки на Rust, Go, C і JavaScript. Даних такий обсяг:

- 316 повідомлень завдовжки 0–4096 байтів, зокрема на межах блоків 32, 64 і 128;
- 300 ключів і блоків ГОСТ 28147 і 141 повідомлення завдовжки 0–1023 байти для його CFB та імітовставки;
- по 60 ключів і блоків Калини на кожну з 5 комбінацій блок/ключ (128/128, 128/256, 256/256, 256/512, 512/512);
- по 10 ключів і підписів на кожну з 10 кривих, з гешами довжиною 1, 32, 48 і 64 байти та нульовим гешем.

Підписи перевіряються в обидва боки. Для CMS
[`ua-cryptography-pki`](https://crates.io/crates/ua-cryptography-pki) 0.1.6 випускає ключі й самопідписані
сертифікати на кривих 163, 179, 257 і 431 біт і підписує CAdES-B; uacrypto перевіряє ці сертифікати й
підписи, підписує тими самими ключами, а `ua-cryptography-pki` перевіряє підписи uacrypto разом із
`signingCertificateV2`. `make tsa` (мережа) робить CAdES-T з позначками справжнього TSA Дії: uacrypto
перевіряє CAdES-T `ua-cryptography-pki`, а той — CAdES-T uacrypto разом із ланцюжком TSA до кореня ЦЗО.

| Реалізація | ГОСТ 34.311 | Купина 256/384/512 | ГОСТ 28147 | Калина ¹ | ДСТУ 4145: ключ з d, розбір ключа, перевірка підпису uacrypto | uacrypto перевіряє їхні підписи |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| [`ua-cryptography-*`](https://crates.io/crates/ua-cryptography-dstu4145) 0.1.6 (Rust) | ✅ 314/316 ⁷ | ✅ 948/948 | ✅ 600/600 ¹ | ✅ 600/600 | ✅ 300/300 ² | ✅ 100/100 ² |
| [RustCrypto `kupyna`](https://crates.io/crates/kupyna) 0.1.0 (Rust) | — | ✅ 948/948 | — | — | — | — |
| [`ua-cryptography-pki`](https://crates.io/crates/ua-cryptography-pki) 0.1.6 (Rust): CMS | — | — | — | — | ✅ 24/28 CMS-підписів uacrypto ⁷ | ✅ 24/28 сертифікатів і 24/28 CMS-підписів ⁷ |
| [`structured-dstu4145`](https://crates.io/crates/structured-dstu4145) 0.20.2 (Rust) | ✅ 314/316 ⁷ | ✅ 948/948 | — | — | ✅ 100/100 ³ | — ⁴ |
| [`jkurwa`](https://github.com/dstucrypt/jkurwa) 1.22.9 і `gost89` 0.1.12 (JS) | ✅ 314/316 ⁷ | — | ✅ 300/300, CFB 280/280, імітовставка 280/280 ⁶ | — | ✅ 81/81 ⁵ | ✅ 27/27 ⁵ |
| [`crypto-dstu`](https://github.com/amaneshi/crypto-dstu) `d16ff7a` (Go) | ✅ 316/316 | ✅ 948/948 | ✅ 300/300, CFB 282/282 ¹, імітовставки немає | ✅ 600/600 | ✅ 300/300 | ✅ 100/100 |
| [`@li0ard/dstu`](https://github.com/li0ard/dstu) 0.2.0 (TypeScript) | — | ✅ 948/948 | — | ✅ 600/600 | ✅ 200/200 ⁸ | ✅ 100/100 ⁸ |
| [UAPKI](https://github.com/specinfo-ua/UAPKI) `uapkic` `1996c0f` (C, `make uapki`) | ✅ 316/316 | ✅ 948/948 | ✅ 300/300, CFB 280/280, імітовставка 282/282 | ✅ 600/600 | ✅ 180/180 ⁹ | ✅ 90/90 ⁹ |

¹ шифрування й розшифрування.
² `ua-cryptography-dstu4145` іде буквою стандарту: геш подається старшим байтом уперед,
підпис кодується як `S‖R` big-endian. ІІТ і uacrypto читають геш як little-endian
і кодують підпис як `r‖s` little-endian. Математика збігається, а формати звірка перетворює.
³ перевірка підпису у форматі ІІТ `r‖s` little-endian, закодованого `MarshalSignature`, на всіх 10 кривих.
⁴ крейт лише перевіряє підписи.
⁵ `jkurwa` має лише криві 191, 257 і 431 біт; нульовий геш (ДСТУ 4145 замінює його на 1) вона
не підписує й відхиляє його правильний підпис, тому ці випадки не звіряються.
⁶ імітовставка 32 і 64 біти; повідомлення рівно з одного блока `gost89` доповнює нульовим блоком
(як OpenSSL GOST engine), а uacrypto і cryptonite — ні, тож такий випадок не звіряється.
⁷ порожнє повідомлення uacrypto, як сертифіковані cryptonite й UAPKI і `crypto-dstu`, гешує разом із
нульовим блоком доповнення, як буквально написано в заключному етапі ГОСТ 34.311 (`5df74e64…`); ця
бібліотека блока не гешує (`da37bdf4…`), тож порожні повідомлення, а в CMS — підписи порожнього вмісту з
ГОСТ 34.311, не звіряються.
⁸ як і `ua-cryptography-dstu4145`, іде буквою стандарту (геш big-endian, підпис `s‖r` big-endian);
звірка перетворює формати. Розбору стислого ключа окремо від перевірки підпису бібліотека не має.
⁹ `dstu4145_sign` і `dstu4145_verify` беруть лише геші довжиною 32, 48 і 64 байти; однобайтові випадки
не звіряються.

`make czo` перевіряє кожен сертифікат із публічного пакета ЦСК
[ЦЗО](https://czo.gov.ua/download/certificates/CACertificates.p7b) ключем його видавця: з 1003
сертифікатів **606 підписів ДСТУ 4145 перевірено, 0 відхилено**; решта — RSA/ECDSA (394) або без
видавця в пакеті (3).

Звірка не порожня: якщо зіпсувати геш, шифротекст або підпис, кожна реалізація це помічає
і `make` завершується з помилкою.

## ⚠️ Безпека

За сталий час (без залежності від секретних даних у розгалуженнях і зверненнях до
пам'яті) на 64-розрядних платформах виконуються:

- ДСТУ 4145: `GenerateKey`, `NewPrivateKey`, `PrivateKey.Bytes` і `Sign` — поле на
  64-бітних лімбах, драбина Монтгомері для секретних скалярів, арифметика за модулем
  порядку кривої без гілок;
- «Калина»: розгортання ключа, шифрування і розшифрування блокового шифру; режими
  (CTR, CFB, CMAC, GMAC, GCM, CCM, XTS, обгортання ключа) — без розгалужень і звернень до таблиць за
  секретом поза самим шифром; часовий тест охоплює CMAC, GMAC, перевірку тега GCM, CCM, XTS і
  `Unwrap`. GHASH виконується з прапорцем DIT процесора
  (`subtle.WithDataIndependentTiming`): без нього ядра Apple M рахують нульові дані помітно швидше;
- «Купина»: функція стиснення;
- ГОСТ 28147-89: раунд шифру; гамування й імітовставка — без розгалужень за секретом поза раундом;
- ГОСТ 34.311 (хеш): через раунд ГОСТ 28147, окремо часовим тестом не перевіряється;
- «Струмок»: ініціалізація й генерація гами (перетворення T — S-блоки й MDS «Калини»,
  множення на α і α⁻¹ — масками в GF(2^8)).

Заміни S-блоків виконуються повним проходом по таблиці з масками, множення в GF(2^8) —
масками, без звернень до пам'яті за секретним індексом.

Це перевіряє статистичний тест dudect (`internal/ctcheck`): у CI він запускається на
linux/amd64 і блокує випуск релізу. Локально:
`go test -tags ctcheck -count=1 -timeout 60m ./internal/ctcheck`; результат надійний
на linux/amd64. Тест охоплює представників: ДСТУ 4145 M257, «Калина-128» з режимами, «Купина-256»,
ГОСТ 28147 з ДКЕ1; контрольний зразок `big.Int.Exp` має провалити тест. 32-розрядні
збірки дають правильні результати, але сталий час для них не заявляється і не
перевіряється.

Сталий час не заявляється для `Verify`, `ParsePublicKey`, `PublicKey.Bytes`,
`CurveFromParams`, а також для розбору і перевірки в `pki`: вони працюють з відкритими
даними. Підпис у `pki` виконує той самий сталочасовий `Sign`.
Поза межами захисту: атаки за енергоспоживанням і збої (fault).

Затирання ключів: `PrivateKey.Destroy` у `dstu4145` і `gost3410` перезаписує скаляр нулями, а `pki` затирає
розшифрований PKCS#8, ключі PBKDF2 і проміжні копії `d`, коли відкриває й пише ключові файли, а в конвертах —
ключ шифрування вмісту й KEK. `gost28147.Destroy` затирає ключ блока з `NewCipher` чи MAC з `NewMAC`, далі вони
панікують; `pki` і генератор `dstu4145.NewPRNG` (при зміні ключа) викликають його самі. `gost34311` затирає
ключі кроку стиснення, виведені з даних (з пароля в PBKDF2), і копію буфера в `Sum`. Копій, які
раніше зробило середовище Go (перенесений стек, копія ключа за значенням, байти з `Bytes`,
ключовий файл), він не досягає. Зібрані з `GOEXPERIMENT=runtimesecret` (Go 1.26+),
`GenerateKey`, `NewPrivateKey`, `Sign` і `ECDH` (`dstu4145`; у `gost3410` — без `ECDH`) виконуються в `runtime/secret.Do`: регістри,
стек і тимчасові алокації затираються після виклику. Діє на linux/amd64 і linux/arm64, на
інших платформах експеримент нічого не робить.

Код не проходив аудиту. Для кваліфікованого електронного підпису використовуйте
сертифіковані засоби КЗІ.

## Ліцензія

[MIT](LICENSE). Частина коду портована з Bouncy Castle Crypto Package (ліцензія MIT);
текст обох ліцензій — у файлі [LICENSE](LICENSE).
