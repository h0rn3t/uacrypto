# uacrypto

[![Go Reference](https://pkg.go.dev/badge/github.com/h0rn3t/uacrypto.svg)](https://pkg.go.dev/github.com/h0rn3t/uacrypto)
[![test](https://github.com/h0rn3t/uacrypto/actions/workflows/test.yml/badge.svg)](https://github.com/h0rn3t/uacrypto/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/h0rn3t/uacrypto/graph/badge.svg)](https://app.codecov.io/gh/h0rn3t/uacrypto)
![Go](https://img.shields.io/badge/go-1.27-00ADD8)
![License](https://img.shields.io/badge/license-MIT-green)

Українські криптографічні стандарти на чистому Go: ДСТУ 4145-2002, ГОСТ 34.311-95,
ДСТУ 7564:2014 «Купина», ДСТУ 7624:2014 «Калина» та ГОСТ 28147-89.

- **Без залежностей** — лише стандартна бібліотека Go.
- **Сумісність байт у байт** з Bouncy Castle та бібліотекою ІІТ «Користувач ЦСК» (EU Sign):
  ті самі геші, те саме кодування ключів, підписи перевіряються в обидва боки.
- **Звичні інтерфейси Go** — `hash.Hash`, `cipher.Block`, `io.Reader` для випадковості.

## Пакети

| Пакет | Стандарт | Що вміє |
|---|---|---|
| [`dstu4145`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/dstu4145) | ДСТУ 4145-2002 — цифровий підпис на еліптичних кривих | усі 10 іменованих кривих (зокрема M257), генерація ключів, підпис, перевірка, стиснене кодування відкритого ключа, підпис `r‖s` у форматі ІІТ |
| [`gost34311`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/gost34311) | ГОСТ 34.311-95 — функція гешування | `hash.Hash`, ДКЕ №1 за замовчуванням або власний S-блок |
| [`kupyna`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/kupyna) | ДСТУ 7564:2014 «Купина» — функція гешування | `hash.Hash` на 256, 384 і 512 біт |
| [`kalyna`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/kalyna) | ДСТУ 7624:2014 «Калина» — блоковий шифр | `cipher.Block` з блоком 128, 256 і 512 біт; CMAC, GCM, CCM, XTS і обгортання ключів |
| [`pki`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/pki) | X.509 і CMS з ДСТУ 4145 | ключ ДСТУ 4145 із сертифіката (явні параметри чи OID кривої, ДКЕ, le/be), РНОКПП і ЄДРПОУ власника, перевірка підпису сертифіката (ГОСТ 34.311, Купина-256, Купина-512), створення й перевірка CMS SignedData: файлів `.p7s` (CAdES-BES, CAdES-T і CAdES-X Long) і позначок часу RFC 3161, клієнт TSP, клієнт OCSP і перевірка відповідей OCSP; для ЦСК — випуск сертифікатів з іменами й розширеннями, як у ЦСК, PKCS#10, ключі PKCS#8 у форматі BC, відповіді OCSP і позначки часу, пакети `.p7b` |
| [`gost28147`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/gost28147) | ГОСТ 28147-89 — блоковий шифр | `cipher.Block`, ДКЕ №1, розпакування й пакування ДКЕ параметрів ключа |

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
```

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

`NewCipher128` бере ключ 16 або 32 байти, `NewCipher512` — 64 байти. `CMAC`, `NewCCM`,
`NewXTS`, `Wrap` і `Unwrap` реалізують режими ДСТУ 7624, як їх рахує Bouncy Castle 1.86.
`NewGCM` додатково автентифікує нонс як перший блок AAD: для сумісності з BC
`KGCMBlockCipher` передавайте йому `nonce || additionalData` як AAD. Теги відрізняються
від звичайного ДСТУ GCM; попередні шифротексти без автентифікації нонса не приймаються.
Нонс GCM і CCM має бути завдовжки рівно один блок. Повторний нонс із тим самим ключем
неприпустимий. `crypto/cipher` CTR, CBC, CFB і OFB — інша схема, не лічильник ДСТУ.

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

- еталонні вектори **Bouncy Castle 1.86** для кожного алгоритму й кожної з 10 кривих: ключ,
  кодування точки, підпис, геші на входах від 0 до 1000 байтів;
- реальний підпис кореневого сертифіката тестового ЦСК, який приймає бібліотека ІІТ;
- реальні сертифікати ЗЦ НБУ, ЦЗО, ДКСУ, «Вчасно» і monobank: ГОСТ 34.311, Купина-256 і Купина-512, ключі le і be, крива явними параметрами;
- реальні позначки часу TSA ДПС, ПриватБанку і Дії (CMS з ГОСТ 34.311 і Купиною-256), зокрема зі зміненим вмістом і підписом;
- реальні відповіді OCSP ЦЗО (good і revoked, делегований відповідач за іменем, дві різні криві) і monobank (відповідач за KeyHash, Купина-512);
- контрольні приклади Купини-256 з ДСТУ 7564:2014 і Калини-128/128 з ДСТУ 7624:2014;
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
відтворювані випадкові дані рахують uacrypto та незалежні бібліотеки на Java, Rust і JavaScript. Даних такий обсяг:

- 316 повідомлень завдовжки 0–4096 байтів, зокрема на межах блоків 32, 64 і 128;
- 300 ключів і блоків ГОСТ 28147;
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
| [Bouncy Castle](https://www.bouncycastle.org/) 1.86 (Java) | ✅ 316/316 | ✅ 948/948 | ✅ 300/300 | ✅ 600/600 | ✅ 300/300 | ✅ 100/100 |
| [`ua-cryptography-*`](https://crates.io/crates/ua-cryptography-dstu4145) 0.1.6 (Rust) | ✅ 316/316 | ✅ 948/948 | ✅ 600/600 ¹ | ✅ 600/600 | ✅ 300/300 ² | ✅ 100/100 ² |
| [RustCrypto `kupyna`](https://crates.io/crates/kupyna) 0.1.0 (Rust) | — | ✅ 948/948 | — | — | — | — |
| [`ua-cryptography-pki`](https://crates.io/crates/ua-cryptography-pki) 0.1.6 (Rust): CMS | — | — | — | — | ✅ 28/28 CMS-підписів uacrypto | ✅ 28/28 сертифікатів і 28/28 CMS-підписів |
| [`structured-dstu4145`](https://crates.io/crates/structured-dstu4145) 0.20.2 (Rust) | ✅ 316/316 | ✅ 948/948 | — | — | ✅ 100/100 ³ | — ⁴ |
| [`jkurwa`](https://github.com/dstucrypt/jkurwa) 1.22.9 і `gost89` 0.1.12 (JS) | ✅ 316/316 | — | ✅ 300/300 | — | ✅ 81/81 ⁵ | ✅ 27/27 ⁵ |

¹ шифрування й розшифрування.
² `ua-cryptography-dstu4145` іде буквою стандарту: геш подається старшим байтом уперед,
підпис кодується як `S‖R` big-endian. BC, ІІТ і uacrypto читають геш як little-endian
і кодують підпис як `r‖s` little-endian. Математика збігається, а формати звірка перетворює.
³ перевірка підпису у форматі ІІТ `r‖s` little-endian, закодованого `MarshalSignature`, на всіх 10 кривих.
⁴ крейт лише перевіряє підписи.
⁵ `jkurwa` має лише криві 191, 257 і 431 біт; нульовий геш (ДСТУ 4145 замінює його на 1) вона
не підписує й відхиляє його правильний підпис, тому ці випадки не звіряються.

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
- «Калина»: розгортання ключа, шифрування і розшифрування;
- «Купина»: функція стиснення;
- ГОСТ 28147-89: раунд шифру.

Заміни S-блоків виконуються повним проходом по таблиці з масками, множення в GF(2^8) —
масками, без звернень до пам'яті за секретним індексом.

Це перевіряє статистичний тест dudect (`internal/ctcheck`): у CI він запускається на
linux/amd64 і блокує випуск релізу. Локально:
`go test -tags ctcheck -count=1 -timeout 30m ./internal/ctcheck`; результат надійний
на linux/amd64. Тест охоплює представників: ДСТУ 4145 M257, «Калина-128», «Купина-256»,
ГОСТ 28147 з ДКЕ1; контрольний зразок `big.Int.Exp` має провалити тест. 32-розрядні
збірки дають правильні результати, але сталий час для них не заявляється і не
перевіряється.

Сталий час не заявляється для `Verify`, `ParsePublicKey`, `PublicKey.Bytes`,
`CurveFromParams`, `pki` і ГОСТ 34.311 (хеш): вони працюють з відкритими даними.
Поза межами захисту: атаки за енергоспоживанням і збої (fault), занулення ключового
матеріалу в пам'яті.

Код не проходив аудиту. Для кваліфікованого електронного підпису використовуйте
сертифіковані засоби КЗІ.

## Плани

- [x] X.509: ключ ДСТУ 4145 і перевірка підпису сертифіката
- [x] CMS SignedData: перевірка підписів (`.p7s`, позначки часу)
- [x] Створення підписів CMS (CAdES-BES)
- [x] TSP: клієнт, перевірка позначок часу, CAdES-T
- [x] OCSP: клієнт і перевірка відповідей
- [x] CAdES-X Long (дані для довготривалої перевірки)
- [x] Випуск сертифікатів, PKCS#10, ключі PKCS#8, відповіді OCSP і позначки часу для ЦСК
- [x] CMS у BER
- [x] Кодування підпису `r || s` як частина API
- [x] ДСТУ 7624:2014 «Калина» (блоковий шифр)
- [x] Режими «Калини» з ДСТУ 7624: CMAC, GCM, CCM, XTS, обгортання ключів
- [x] Реалізація за сталий час

## Ліцензія

[MIT](LICENSE). Частина коду портована з Bouncy Castle Crypto Package (ліцензія MIT);
текст обох ліцензій — у файлі [LICENSE](LICENSE).
