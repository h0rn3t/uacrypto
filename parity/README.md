# Звірка з іншими реалізаціями

Диференціальна перевірка: uacrypto рахує випадкові (але відтворювані, з фіксованим зерном)
випадки, а Bouncy Castle і Rust-бібліотеки рахують те саме незалежно. Підписи йдуть в обидва
боки: чужі реалізації перевіряють підписи uacrypto і підписують ті самі геші тими самими ключами,
а uacrypto перевіряє їхні підписи.

```sh
cd parity
make
```

Потрібні `go`, `java`/`javac` (17+), `cargo`, `curl`. Інший JDK:
`make JAVA=/opt/homebrew/opt/openjdk/bin/java JAVAC=/opt/homebrew/opt/openjdk/bin/javac`. Bouncy Castle завантажується з Maven Central і
перевіряється за SHA-256. Будь-яка розбіжність — ненульовий код виходу.

| Файл | Що робить |
|---|---|
| [`main.go`](main.go) | `gen` — випадки від uacrypto; `verify` — перевірка чужих підписів |
| [`java/Check.java`](java/Check.java) | Bouncy Castle 1.86 |
| [`rust/src/main.rs`](rust/src/main.rs) | `ua-cryptography-*`, RustCrypto `kupyna`, `structured-dstu4145` |

## Формати, які треба узгоджувати

- **Bouncy Castle, ІІТ, `structured-dstu4145`, uacrypto** подають геш у ДСТУ 4145 так, як його
  видала геш-функція (байти ГОСТ 34.311 як little-endian число); підпис у форматі ІІТ — `r‖s`,
  кожне little-endian.
- **`ua-cryptography-dstu4145`** іде буквою стандарту: геш старшим байтом уперед (розвернутий
  вихід ГОСТ 34.311), підпис `D = S‖R` big-endian. Математика та сама, але без перетворення цих
  двох форматів підписи між ним і рештою не перевіряються.
