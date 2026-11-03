# uacrypto

[![Go Reference](https://pkg.go.dev/badge/github.com/h0rn3t/uacrypto.svg)](https://pkg.go.dev/github.com/h0rn3t/uacrypto)
![Go](https://img.shields.io/badge/go-1.27-00ADD8)
![License](https://img.shields.io/badge/license-MIT-green)

Українські криптографічні стандарти на чистому Go: ДСТУ 4145-2002, ГОСТ 34.311-95,
ДСТУ 7564:2014 «Купина» та ГОСТ 28147-89.

- **Без залежностей** — лише стандартна бібліотека Go.
- **Сумісність байт у байт** з Bouncy Castle та бібліотекою ІІТ «Користувач ЦСК» (EU Sign):
  ті самі геші, те саме кодування ключів, підписи перевіряються в обидва боки.
- **Звичні інтерфейси Go** — `hash.Hash`, `cipher.Block`, `io.Reader` для випадковості.

## Пакети

| Пакет | Стандарт | Що вміє |
|---|---|---|
| [`dstu4145`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/dstu4145) | ДСТУ 4145-2002 — цифровий підпис на еліптичних кривих | усі 10 іменованих кривих (зокрема M257), генерація ключів, підпис, перевірка, стиснене кодування відкритого ключа |
| [`gost34311`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/gost34311) | ГОСТ 34.311-95 — функція гешування | `hash.Hash`, ДКЕ №1 за замовчуванням або власний S-блок |
| [`kupyna`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/kupyna) | ДСТУ 7564:2014 «Купина» — функція гешування | `hash.Hash` на 256, 384 і 512 біт |
| [`gost28147`](https://pkg.go.dev/github.com/h0rn3t/uacrypto/gost28147) | ГОСТ 28147-89 — блоковий шифр | `cipher.Block`, ДКЕ №1 і розпакування ДКЕ з параметрів ключа |

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
	curve, _ := dstu4145.NamedCurve(6) // M257 — крива кваліфікованих сертифікатів
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

Бібліотека повертає `r` і `s` як числа. У сертифікатах, OCSP і CMS українські ЦСК
записують підпис як `r || s`, кожне число в little-endian фіксованої довжини
(для M257 — по 32 байти, як у test-ca та ІІТ):

```go
size := (curve.Order().BitLen() + 7) / 8
sig := append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
slices.Reverse(sig[:size])
slices.Reverse(sig[size:])
```

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

- Для кожного алгоритму й кожної з 10 кривих є еталонні вектори, згенеровані
  **Bouncy Castle 1.86**: ключ, кодування точки, підпис, геші на входах від 0 до 1000 байтів.
- Є реальний підпис кореневого сертифіката тестового ЦСК, який приймає бібліотека ІІТ.
- Купина-256 від порожнього рядка збігається з контрольним прикладом ДСТУ 7564:2014.
- Розбір відкритого ключа покрито фаз-тестом.

```sh
go test -race ./...
```

## ⚠️ Безпека

Арифметика побудована на `math/big` і **не виконується за сталий час**: за часом роботи
можна відновити приватний ключ. Код не проходив аудиту. Бібліотека призначена для
тестових середовищ, перевірки підписів і сумісності, а **не для захисту бойових ключів**.
Для кваліфікованого електронного підпису використовуйте сертифіковані засоби КЗІ.

## Плани

- [ ] Структури PKI: X.509, PKCS#10, OCSP, TSP (RFC 3161), CMS на ДСТУ 4145
- [ ] Кодування підпису `r || s` як частина API
- [ ] ДСТУ 7624:2014 «Калина»
- [ ] Реалізація за сталий час

## Ліцензія

[MIT](LICENSE). Частина коду портована з Bouncy Castle Crypto Package (ліцензія MIT);
текст обох ліцензій — у файлі [LICENSE](LICENSE).
