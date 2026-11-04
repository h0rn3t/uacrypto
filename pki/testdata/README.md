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

Позначки часу (RFC 3161), отримані 2026-11-04 від публічних TSA на запит із гешем рядка
`uacrypto test`; у файлі — сам токен, CMS SignedData з TSTInfo:

| Файл | TSA | Геш і підпис |
|---|---|---|
| `tsa-tax-gost.p7s` | http://ca.tax.gov.ua/services/tsp/ | ГОСТ 34.311, `dstu4145le` |
| `tsa-privatbank-gost.p7s` | http://acsk.privatbank.ua/services/tsp/ | ГОСТ 34.311, `dstu4145le` |
| `tsa-diia-kupyna.p7s` | http://ca.diia.gov.ua/services/tsp/ | Купина-256, ДСТУ 4145 + Купина-256 |

Відповіді OCSP, отримані 2026-11-04 на запити з CertID на Купині-256 і nonce `uacrypto-test-nonce`;
у файлі — увесь OCSPResponse:

| Файл | Відповідач | Сертифікат (видавець, серійний номер) | Статус |
|---|---|---|---|
| `ocsp-czo-good.der` | http://czo.gov.ua/services/ocsp/ | `czo-2601.der`, `572B26CB…E7010000` («Вчасно», `vchasno-kupyna.der`) | good |
| `ocsp-czo-revoked.der` | http://czo.gov.ua/services/ocsp/ | `czo-2020.der`, `05E19E2C…06010000` з CRL ЦЗО-2020 | revoked 2021-10-07 15:56:54 UTC, superseded |
| `ocsp-monobank-good.der` | http://ca.monobank.ua/services/ocsp/dstu/ | `monobank-ca.der`, `107D4BC9…48F70463` (`monobank-cmp-kupyna512.der`) | good |
