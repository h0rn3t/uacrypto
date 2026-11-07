# Звірка з іншими реалізаціями

Диференціальна перевірка: uacrypto рахує випадкові (але відтворювані, з фіксованим зерном)
випадки, а Bouncy Castle, Rust-бібліотеки і jkurwa (JS) рахують те саме незалежно. Підписи йдуть в обидва
боки: чужі реалізації перевіряють підписи uacrypto і підписують ті самі геші тими самими ключами,
а uacrypto перевіряє їхні підписи.

```sh
cd parity
make
```

Потрібні `go`, `java`/`javac` (17+), `cargo`, `bun`, `curl`. Інший JDK:
`make JAVA=/opt/homebrew/opt/openjdk/bin/java JAVAC=/opt/homebrew/opt/openjdk/bin/javac`. Bouncy Castle завантажується з Maven Central і
перевіряється за SHA-256, `jkurwa` і `gost89` ставляться точно за `jkurwa/bun.lock`. Будь-яка розбіжність — ненульовий код виходу.

| Файл | Що робить |
|---|---|
| [`main.go`](main.go) | `gen` — випадки від uacrypto; `verify` — перевірка чужих підписів; `cms` — звірка CMS; `tsa` — CAdES-T зі справжнім TSA; `czo` — корпус ЦЗО; `envelope-gen`, `envelope-check` — конверти ([`envelope.go`](envelope.go)); `crl-gen`, `crl-check` — CRL ([`crl.go`](crl.go)) |
| [`java/Check.java`](java/Check.java) | Bouncy Castle 1.86 |
| [`java/CRL.java`](java/CRL.java) | CRL через JCA-провайдер Bouncy Castle 1.86 в обидва боки: `X509CRL.verify` CRL uacrypto, номер, дельта-індикатор і записи; той самий CRL від BC (`V2TBSCertListGenerator`, `GOST3411WITHDSTU4145LE`) для `pki.ParseRevocationList` |
| [`jkurwa/envelope.mjs`](jkurwa/envelope.mjs) | конверти CMS EnvelopedData у обидва боки з `jkurwa` |
| [`jkurwa/check.mjs`](jkurwa/check.mjs) | [`jkurwa`](https://github.com/dstucrypt/jkurwa) 1.22.9 (ДСТУ 4145) і [`gost89`](https://github.com/dstucrypt/gost89) 0.1.12 (ГОСТ 34.311, ГОСТ 28147: блок, CFB, імітовставка 32 і 64 біти) |
| [`rust/src/main.rs`](rust/src/main.rs) | `ua-cryptography-*` (зокрема `dstu7624` для Калини і `pki` для CMS), RustCrypto `kupyna`, `structured-dstu4145` |
| [`iit/`](iit) | бібліотека ІІТ «Користувач ЦСК» (EU Sign) через `dlopen`, окремий модуль із cgo |
| [`cryptonite/prng.c`](cryptonite/prng.c) | генератор ДСТУ 4145 сертифікованої [cryptonite](https://github.com/privat-it/cryptonite) (`make cryptonite`) |

## Бібліотека ІІТ

ІІТ постачає сертифіковану бібліотеку лише бінарною й за власною ліцензією, тож у репозиторії її немає,
а [`iit/lib.go`](iit/lib.go) оголошує тільки ті кілька функцій, які викликає. Потрібні cgo і каталог
бібліотеки з її модулями; ключі, сертифікати й `osplm.ini` не потрібні:

```sh
make iit IIT_LIB=/шлях/до/euscp.dylib   # або euscp.so
```

Звірка тримає ІІТ і uacrypto прикладів зі стандартів (Купина-256 і Купина-512 з ДСТУ 7564, Калина 256/256
з ДСТУ 7624) і порівнює ГОСТ 34.311 (ДКЕ №1), Купину-256/384/512 на всіх довжинах до трьох блоків
Купини-512 і на кількох довгих, Калину-256 у режимі CFB (`kalyna.NewCFB`) на всіх довжинах до семи блоків і
MAC Калини-256 (`kalyna.CMAC`, 64, 128 і 256 біт) на всіх довжинах до чотирьох блоків. Чим ІІТ відрізняється:

- **Порожнє повідомлення** ІІТ не гешує й не автентифікує («Incorrect parameter»); uacrypto гешує його
  за стандартом, а MAC рахує як MAC одного нульового блока.
- **Неповні блоки CFB і MAC** ІІТ рахує так само, як сертифікована відкрита бібліотека
  [cryptonite](https://github.com/privat-it/cryptonite) і приклади ДСТУ 7624, а отже й uacrypto: хвіст CFB
  шифрується *останніми* байтами блока гами, а неповний останній блок MAC доповнюється `80 00…` і
  маскується E(`01 00…`) замість E(0). Bouncy Castle і `ua-cryptography-dstu7624`, перекладений з нього,
  беруть перші байти гами CFB і такі MAC відхиляють.

## cryptonite

Генератор псевдовипадкових чисел, з яким cryptonite генерує ключі й підписує ДСТУ 4145 (`PRNG_MODE_DSTU`),
домішує поточний час, тож тестових векторів у cryptonite немає. `make cryptonite` завантажує вихідний код
cryptonite з фіксованого коміту (перевірка SHA-256), збирає генератор C-компілятором із годинником,
підставленим замість `time(NULL)`, друкує таблицю з восьми випадків, порівнює її байт у байт із
`dstu4145/testdata/cryptonite_prng.txt` і запускає `TestPRNGCryptonite`, який перевіряє на тій самій
таблиці `dstu4145.NewPRNG`, `Read` і `Seed`. Потрібні `curl` і `cc`; мережа — лише для першого завантаження.

## Формати, які треба узгоджувати

- **Bouncy Castle, ІІТ, `structured-dstu4145`, `jkurwa`, uacrypto** подають геш у ДСТУ 4145 так, як його
  видала геш-функція (байти ГОСТ 34.311 як little-endian число); підпис у форматі ІІТ — `r‖s`,
  кожне little-endian.
- **`ua-cryptography-dstu4145`** іде буквою стандарту: геш старшим байтом уперед (розвернутий
  вихід ГОСТ 34.311), підпис `D = S‖R` big-endian. Математика та сама, але без перетворення цих
  двох форматів підписи між ним і рештою не перевіряються.
- **Імітовставку ГОСТ 28147 повідомлення рівно з одного блока** `gost89` рахує, як OpenSSL GOST engine, над цим
  блоком і дописаним нульовим блоком; uacrypto, як cryptonite (`gost28147_final_mac`), — над одним блоком. Звірка
  такі випадки пропускає; на решті довжин, зокрема порожньому повідомленні й неповних блоках, MAC збігається.
  Гамування (`gost28147.NewCTR`) у `gost89` немає.
- **`jkurwa`** має лише 3 з 10 кривих ДСТУ 4145 (191, 257 і 431 біт), решту випадків підписів звірка
  пропускає. Нульовий геш, який ДСТУ 4145 замінює на 1, `jkurwa` не підписує («Pass non zero value»)
  і відхиляє правильний підпис такого гешу, тож ці випадки теж пропускаються.
