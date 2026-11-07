# Сертифікати для тестів

Незмінені публічні сертифікати ЦСК із пакета ЦЗО
[CACertificates.p7b](https://czo.gov.ua/download/certificates/CACertificates.p7b), завантаженого
2026-11-03 (SHA-256 пакета `efc6a4ecf5ca10dd099335fbf2c1173d597110b4eb431cb89652e7b7369029c4`).
`nbu-root-*.der` і `vchasno-*.der`, `dksu-ocsp-be.der` — ті самі сертифікати, що лежать у тестових
даних крейтів `structured-dstu4145` і `structured-pkix` 0.20.2.

| Файл | Що це | Видавець |
|---|---|---|
| `nbu-root-gost.der` | кореневий сертифікат ЗЦ НБУ, підпис ДСТУ 4145 + ГОСТ 34.311, крива m=431 явними параметрами | він сам |
| `nbu-root-kupyna.der` | кореневий сертифікат ЗЦ НБУ, підпис ДСТУ 4145 + Купина-256 | він сам |
| `czo-2020.der` | ЦЗО, UA-43220851-2020 | — |
| `vchasno-gost.der` | КНЕДП «Вчасно Сервіс», підпис ГОСТ 34.311 | `czo-2020.der` |
| `czo-2601.der` | ЦЗО, UA-43220851-2601 | — |
| `vchasno-kupyna.der` | КНЕДП «Вчасно Сервіс», підпис ДСТУ 4145 + Купина-256 | `czo-2601.der` |
| `dksu-ca.der` | АЦСК ДКСУ | — |
| `dksu-ocsp-be.der` | OCSP-сервер АЦСК ДКСУ, ключ з OID `dstu4145be` | `dksu-ca.der` |
| `monobank-ca.der` | КНЕДП monobank \| Universal Bank | — |
| `monobank-cmp-kupyna512.der` | CMP-сервер КНЕДП monobank, підпис ДСТУ 4145 + Купина-512 | `monobank-ca.der` |
| `ukrgasbank-tsp.der` | TSP-сервер КНЕДП АБ «УКРГАЗБАНК», серійний номер `2D8136B9…58000000`; ЄДРПОУ `23697280` у `subjectDirectoryAttributes` | ЗЦ НБУ, UA-00032106-2019 |

Позначки часу (RFC 3161), отримані 2026-11-04 від публічних TSA на запит із гешем рядка
`uacrypto test`; у файлі — сам токен, CMS SignedData з TSTInfo:

| Файл | TSA | Геш і підпис |
|---|---|---|
| `tsa-tax-gost.p7s` | http://ca.tax.gov.ua/services/tsp/ | ГОСТ 34.311, `dstu4145le` |
| `tsa-privatbank-gost.p7s` | http://acsk.privatbank.ua/services/tsp/ | ГОСТ 34.311, `dstu4145le` |
| `tsa-diia-kupyna.p7s` | http://ca.diia.gov.ua/services/tsp/ | Купина-256, ДСТУ 4145 + Купина-256 |
| `tsa-diia-kupyna-ber.p7s` | `tsa-diia-kupyna.p7s` у BER (див. нижче) | Купина-256, ДСТУ 4145 + Купина-256 |

Файли `*-ber.p7s` зроблено 2026-11-04 класами ASN.1 Bouncy Castle 1.86 (`BERSequence`, `BERTaggedObject`,
`BERSet`, `BEROctetString`) з DER-файлів поруч, як їх пишуть потокові засоби: ContentInfo, SignedData,
EncapsulatedContentInfo і набір сертифікатів мають невизначену довжину, eContent — складений OCTET STRING
шматками по 4 байти (`czo-test-…`) і по 40 байтів (`tsa-diia-…`). SignerInfo, а з ним підписані атрибути,
значення підпису й вкладені позначки часу й відповіді OCSP, лишилися байт у байт такими, як були.

Тестові приклади кваліфікованого підпису ЦЗО ([czo.gov.ua/testexamples](https://czo.gov.ua/testexamples),
наказ Мінцифри № Н 191), завантажені 2026-11-04 без змін: файл «Test\r\n», підписаний разом із даними
(enveloped) на тестовому ЦСК «Адміністратор ІТС ЦЗО (CA TEST)». Сертифікати TSA й OCSP-серверів
тестового ЦСК узято з файлів «з повними даними ЦСК»: у звичайних CAdES-T і CAdES-X Long їх немає.

| Файл | Категорія ЦЗО | Геш і підпис |
|---|---|---|
| `czo-test-t-kupyna.p7s` | CAdES-T | Купина-256, ДСТУ 4145 |
| `czo-test-c-gost.p7s` | CAdES-C | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-xlong-kupyna.p7s` | CAdES-X Long (повні дані для перевірки) | Купина-256, ДСТУ 4145 |
| `czo-test-xlong-gost.p7s` | CAdES-X Long (повні дані для перевірки) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-xlong-full-kupyna.p7s` | CAdES-X Long (повні дані ЦСК для перевірки) | Купина-256, ДСТУ 4145 |
| `czo-test-xlong-full-gost.p7s` | CAdES-X Long (повні дані ЦСК для перевірки) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-xlong-full-gost-ber.p7s` | `czo-test-xlong-full-gost.p7s` у BER (див. нижче) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-asics-bes-gost.asics` | ASiC-S, CAdES-BES (контейнер `DSTU/CAdES-BES` ЦЗО, 2026-11-06) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-asice-t-kupyna.asice` | ASiC-E, CAdES-T (`DSTU-7564/CAdES-T`, 2026-11-06) | Купина-256, ДСТУ 4145 |
| `czo-test-asice-xlong-gost.asice` | ASiC-E, CAdES-X Long (`DSTU/CAdES-X_Long`, 2026-11-06) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-asics-xades-gost.asics` | ASiC-S, XAdES-B-B (`DSTU/XAdES-B-B`, 2026-11-06) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-asice-xades-bt-kupyna.asice` | ASiC-E, XAdES-B-T (`DSTU-7564/XAdES-B-T`, 2026-11-06) | Купина-256, ДСТУ 4145 |
| `czo-test-xades-bb-gost.xml` | XAdES-B-B, вбудований підпис (`XAdES/DSTU/enveloped/XAdES-B-B/test.xml`, 2026-11-06) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-xades-bt-kupyna-detached.xml` | XAdES-B-T, відокремлений підпис файла `Test.xml` (`XAdES/DSTU-7564/detached/XAdES-B-T/sign.xml`, 2026-11-06) | Купина-256, ДСТУ 4145 |
| `czo-test-xades-data.xml` | той файл `Test.xml` (`…/detached/XAdES-B-T/test.xml`) | — |
| `czo-test-xades-blt-gost.xml` | XAdES-B-LT, вбудований підпис (`XAdES/DSTU/enveloped/XAdES-B-LT/test.xml`, 2026-11-06) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-xades-blta-kupyna.xml` | XAdES-B-LTA, вбудований підпис (`XAdES/DSTU-7564/enveloped/XAdES-B-LTA/test.xml`, 2026-11-06) | Купина-256, ДСТУ 4145 |
| `czo-test-pades-bb-gost.pdf` | PAdES-B-B, файл `Test.pdf` (`PAdES/DSTU/PAdES-B-B/Test.pdf`, 2026-11-07) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-pades-bb-kupyna.pdf` | PAdES-B-B (`PAdES/DSTU-7564/PAdES-B-B/Test.pdf`, 2026-11-07) | Купина-256, ДСТУ 4145 |
| `czo-test-pades-bt-gost.pdf` | PAdES-B-T (`PAdES/DSTU/PAdES-B-T/Test.pdf`, 2026-11-07) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-pades-bt-kupyna.pdf` | PAdES-B-T (`PAdES/DSTU-7564/PAdES-B-T/Test.pdf`, 2026-11-07) | Купина-256, ДСТУ 4145 |
| `czo-test-pades-blt-gost.pdf` | PAdES-B-LT, з DSS (`PAdES/DSTU/PAdES-B-LT/Test.pdf`, 2026-11-07) | ГОСТ 34.311, ДСТУ 4145 |
| `czo-test-pades-blta-kupyna.pdf` | PAdES-B-LTA, з DSS і позначкою часу документа (`PAdES/DSTU-7564/PAdES-B-LTA/Test.pdf`, 2026-11-07) | Купина-256, ДСТУ 4145 |
| `cairo-xref-stream.pdf` | непідписаний `Test.pdf` ЦЗО (перші 28879 байтів зразків PAdES), перезаписаний `pdftocairo -pdf` (poppler 26.10.0, cairo 1.18.6, 2026-11-08): лише потік перехресних посилань, каталог, дерево сторінок і `/Info` — у потоці об'єктів | — |
| `czo-test-tsa.der` | сертифікат «TSP-сервер Адміністратора ІТС ЦЗО (CA TEST)» | — |
| `czo-test-ocsp-ca.der` | сертифікат «OCSP-сервер Адміністратора ІТС ЦЗО (CA TEST)» | — |
| `czo-test-ocsp-root.der` | сертифікат «OCSP-сервер Центрального засвідчувального органу (ROOT TEST)» | — |

Зразки PAdES завантажено з `https://czo.gov.ua/download/test_sign/PAdES/<DSTU|DSTU-7564>/<категорія>/Test.pdf`.
Перші 28879 байтів кожного — той самий непідписаний `Test.pdf` (Microsoft Word 2019, гібридна таблиця
перехресних посилань); ІІТ дописує підпис, DSS і позначку часу документа інкрементними оновленнями
з класичними таблицями. Тести беруть з них `Test.pdf` для `SignPAdES`.

Відповіді OCSP, отримані 2026-11-04 на запити з CertID на Купині-256 і nonce `uacrypto-test-nonce`;
у файлі — увесь OCSPResponse:

| Файл | Відповідач | Сертифікат (видавець, серійний номер) | Статус |
|---|---|---|---|
| `ocsp-czo-good.der` | http://czo.gov.ua/services/ocsp/ | `czo-2601.der`, `572B26CB…E7010000` («Вчасно», `vchasno-kupyna.der`) | good |
| `ocsp-czo-revoked.der` | http://czo.gov.ua/services/ocsp/ | `czo-2020.der`, `05E19E2C…06010000` з CRL ЦЗО-2020 | revoked 2021-10-07 15:56:54 UTC, superseded |
| `ocsp-monobank-good.der` | http://ca.monobank.ua/services/ocsp/dstu/ | `monobank-ca.der`, `107D4BC9…48F70463` (`monobank-cmp-kupyna512.der`) | good |

Ключові файли:

| Файл | Що це | Звідки |
|---|---|---|
| `iit-123456.pfx` | PKCS#12 від ІІТ, пароль `123456`: два ключі (криві m=257 і m=431, явні параметри), MAC на ГОСТ 34.311 | cryptonite, `src/storageUtest/resources/pkcs12_by_iit(123456).pfx` |
| `jkurwa-store-a040.dat` | EncryptedPrivateKeyInfo (PBES2, ГОСТ 28147 CFB), пароль `password` | jkurwa 1.22.9, `test/data/STORE_A040.dat` |
| `jkurwa-key40a0.der` | розшифрований `jkurwa-store-a040.dat`: PKCS#8 у записі ІІТ (`d` little-endian) | jkurwa, `test/data/Key40A0.pem`, розкодований з PEM |
| `jkurwa-self-signed-enc-40a0.cer` | сертифікат ключа `jkurwa-key40a0.der`; AKI, який `crypto/x509` відхиляє | jkurwa, `test/data/SELF_SIGNED_ENC_40A0.cer` |
| `jkurwa-key6929.der` | ключ відправника конверта `jkurwa-enc-message.p7`: PKCS#8 у записі ІІТ (`d` little-endian) | jkurwa, `test/data/Key6929.cer` |
| `jkurwa-self-signed-enc-6929.cer` | сертифікат ключа `jkurwa-key6929.der`; AKI, який `crypto/x509` відхиляє | jkurwa, `test/data/SELF_SIGNED_ENC_6929.cer` |
| `jkurwa-key6-40a0.dat` | Key-6.dat у старому сховищі ІІТ (`1.3.6.1.4.1.19398.1.1.1.2`) з ключем `jkurwa-key40a0.der`, пароль `password`; контрольне значення — 4 нульові байти (jkurwa його не перевіряє) | 2026-11-07: ASN.1 `StoreIIT` з jkurwa 1.22.9 (`lib/spec/keystore.js`), ключ `dumb_kdf(пароль, 10000)` і ГОСТ 28147 ECB з gost89 0.1.12; jkurwa `Priv.from_protected` розшифровує його в той самий ключ |
| `jkurwa-key6-iit-123456.dat` | те саме сховище з першим ключем `iit-123456.pfx` (крива m=257), пароль `123456`; відкритий ключ (big-endian) `01e0d6d2…c446cb` — той, що дає jkurwa | 2026-11-07: PKCS#8 розшифрував з PFX jkurwa (`pfx_parse` + `storeload`), сховище — як у рядку вище |
| `jdk-bc-dstu4145.jks` | Sun JKS, пароль `пароль`: ключ ДСТУ 4145 (крива m=257, PKCS#8 Bouncy Castle, `d` = `50bf5cd5…69d1a523`) з самопідписаним сертифікатом і довірений сертифікат `czo-test-ocsp-root.der` | 2026-11-07: ключ і сертифікат — Bouncy Castle 1.86, сховище — `KeyStore.getInstance("JKS")` OpenJDK 27.0.1 |
| `rust-dstu4145.jks` | Sun JKS, пароль `пароль`: той самий ключ у записі ІІТ (`d` little-endian), той самий сертифікат; алгоритм захисту ключа з параметром NULL, як у ПриватБанку | 2026-11-07: `JksKeyStore` з ua-cryptography-pki 0.1.6 (Rust) |

Конверт (CMS EnvelopedData) `jkurwa-enc-message.p7` — `enc_message.p7` з jkurwa 1.22.9: «123» від ключа
`jkurwa-key6929.der` сертифікату `jkurwa-self-signed-enc-40a0.cer`, зроблений із підміненим генератором,
що завжди повертає `12345678901234567890123456789012`. Допоміжна функція тестів jkurwa повертає всі 32 байти
замість запитаної довжини, тож UKM і IV у файлі мають по 32 байти (шифр узяв перші 8 байтів IV).

Списки відкликаних сертифікатів ЦЗО, завантажені 2026-11-06 з точок розповсюдження сертифікатів,
які ЦЗО видав, без змін:

| Файл | Звідки | Видавець | Номер | Записів |
|---|---|---|---|---|
| `czo-2020-full.crl` | http://czo.gov.ua/download/crls/CZO-2020-Full.crl | `czo-2020.der` | 343283 | 2 (серед них `05E19E2C…06010000` з `ocsp-czo-revoked.der`) |
| `czo-2020-delta.crl` | http://czo.gov.ua/download/crls/CZO-2020-Delta.crl | `czo-2020.der` | 343357 | 0 |
| `czo-2026-full.crl` | http://czo.gov.ua/download/crls/CZO-2026-Full.crl | `czo-2601.der` | 342847 | 0 |
| `czo-2026-delta.crl` | http://czo.gov.ua/download/crls/CZO-2026-Delta.crl | `czo-2601.der` | 343350 | 0 |

Генератор ДСТУ 4145 cryptonite (`PRNG_MODE_DSTU`) — `dstu4145/testdata/cryptonite_prng.txt`, 2026-11-07: вісім
випадків (сід, час засівання, 48 байтів виходу, дані для `prng_seed`, час повторного засівання, 32 байти виходу),
які друкує [`parity/cryptonite/prng.c`](../../parity/cryptonite/prng.c) — cryptonite з коміту `3618d340`
(архів GitHub, SHA-256 `7da75f28…f27d8b`) із годинником, підставленим замість `time(NULL)`. Сіди й дані — з
лінійного конгруентного генератора в `prng.c`; `make -C parity cryptonite` відтворює файл і порівнює байт у байт.
