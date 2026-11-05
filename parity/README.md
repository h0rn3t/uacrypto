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
| [`main.go`](main.go) | `gen` — випадки від uacrypto; `verify` — перевірка чужих підписів; `cms` — звірка CMS; `tsa` — CAdES-T зі справжнім TSA; `czo` — корпус ЦЗО |
| [`java/Check.java`](java/Check.java) | Bouncy Castle 1.86 |
| [`jkurwa/check.mjs`](jkurwa/check.mjs) | [`jkurwa`](https://github.com/dstucrypt/jkurwa) 1.22.9 (ДСТУ 4145) і [`gost89`](https://github.com/dstucrypt/gost89) 0.1.12 (ГОСТ 34.311, ГОСТ 28147) |
| [`rust/src/main.rs`](rust/src/main.rs) | `ua-cryptography-*` (зокрема `dstu7624` для Калини і `pki` для CMS), RustCrypto `kupyna`, `structured-dstu4145` |

## Формати, які треба узгоджувати

- **Bouncy Castle, ІІТ, `structured-dstu4145`, `jkurwa`, uacrypto** подають геш у ДСТУ 4145 так, як його
  видала геш-функція (байти ГОСТ 34.311 як little-endian число); підпис у форматі ІІТ — `r‖s`,
  кожне little-endian.
- **`ua-cryptography-dstu4145`** іде буквою стандарту: геш старшим байтом уперед (розвернутий
  вихід ГОСТ 34.311), підпис `D = S‖R` big-endian. Математика та сама, але без перетворення цих
  двох форматів підписи між ним і рештою не перевіряються.
- **`jkurwa`** має лише 3 з 10 кривих ДСТУ 4145 (191, 257 і 431 біт), решту випадків підписів звірка
  пропускає. Нульовий геш, який ДСТУ 4145 замінює на 1, `jkurwa` не підписує («Pass non zero value»)
  і відхиляє правильний підпис такого гешу, тож ці випадки теж пропускаються.
