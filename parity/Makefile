# Звірка uacrypto з Rust-бібліотеками, crypto-dstu (Go), jkurwa і @li0ard/dstu (JS). Потрібні go, cargo, bun, curl.
#   make          — уся звірка; ненульовий код виходу, якщо хоч щось розійшлося
#   make tsa      — CAdES-T з позначками часу справжнього TSA (мережа; TSA_URL змінює сервер)
#   make czo      — перевірити підписи всіх ДСТУ-сертифікатів пакета ЦЗО (окремо: пакет оновлюється)
#   make iit IIT_LIB=…/euscp.dylib — звірка з бібліотекою ІІТ «Користувач ЦСК» (окремо: вона не постачається з репозиторієм)
#   make cryptonite — генератор ДСТУ 4145 cryptonite (C-компілятор; вихідний код завантажується за фіксованим комітом)
#   make uapki    — звірка з uapkic, бібліотекою примітивів UAPKI (cmake і C-компілятор; код за фіксованим комітом)
#   make clean    — прибрати згенероване

TSA_URL    ?= http://ca.diia.gov.ua/services/tsp/
CZO_URL    := https://czo.gov.ua/download/certificates/CACertificates.p7b
CZO_SHA256 := efc6a4ecf5ca10dd099335fbf2c1173d597110b4eb431cb89652e7b7369029c4
OUT        := out
CRYPTONITE_REV    := 3618d340d22e27a6becf97d89c453f8e64068a39
CRYPTONITE_SHA256 := 7da75f28041682c38a7d274dbde64f4d68a1d21f5eb8617e8330ab93c5f27d8b
CRYPTONITE_URL    := https://github.com/privat-it/cryptonite/archive/$(CRYPTONITE_REV).tar.gz
CRYPTONITE_SRC    := $(OUT)/cryptonite-$(CRYPTONITE_REV)/src/cryptonite/c
UAPKI_REV    := 1996c0fe56dbbc69f5b00d67784a5bc3033b57fe
UAPKI_SHA256 := b2df7392abb7c8fe72047580f360b262c793e395a7549f1a6735916dc5b912b3
UAPKI_URL    := https://github.com/specinfo-ua/UAPKI/archive/$(UAPKI_REV).tar.gz
UAPKIC_SRC   := $(OUT)/UAPKI-$(UAPKI_REV)/library/uapkic
UAPKIC_LIB   := $(OUT)/uapkic-build/libuapkic.a
CC         ?= cc
CMAKE      ?= cmake
BUN        ?= bun

.PHONY: all cms envelope tsa czo iit cryptonite uapki clean
SIGS := $(addprefix $(OUT)/,rust_sigs.txt cryptodstu_sigs.txt jkurwa_sigs.txt li0ard_sigs.txt)
all: $(OUT)/cases.txt $(SIGS) cms envelope
	cat $(SIGS) > $(OUT)/foreign_sigs.txt
	go run . verify $(OUT)/foreign_sigs.txt

# CMS: ua-cryptography-pki випускає ключі й сертифікати та підписує, uacrypto перевіряє і підписує тими самими
# ключами, ua-cryptography-pki перевіряє підписи uacrypto
cms: rust/src/main.rs rust/Cargo.toml rust/Cargo.lock main.go $(wildcard ../*/*.go)
	mkdir -p $(OUT)
	cargo run --release --locked -q --manifest-path rust/Cargo.toml -- cms-gen $(OUT)/rust_cms.txt
	go run . cms $(OUT)/rust_cms.txt $(OUT)/go_cms.txt
	cargo run --release --locked -q --manifest-path rust/Cargo.toml -- cms-verify $(OUT)/go_cms.txt

$(OUT)/cases.txt: main.go $(wildcard ../*/*.go)
	mkdir -p $(OUT)
	go run . gen > $@.tmp && mv $@.tmp $@

$(OUT)/rust_sigs.txt: $(OUT)/cases.txt rust/src/main.rs rust/Cargo.toml rust/Cargo.lock
	cargo run --release --locked -q --manifest-path rust/Cargo.toml -- $(OUT)/cases.txt $@

# crypto-dstu — окремий модуль: основний модуль лишається без залежностей
$(OUT)/cryptodstu_sigs.txt: $(OUT)/cases.txt cryptodstu/main.go cryptodstu/go.mod cryptodstu/go.sum
	cd cryptodstu && go run . ../$(OUT)/cases.txt ../$@

li0ard/node_modules: li0ard/package.json li0ard/bun.lock
	cd li0ard && $(BUN) install --frozen-lockfile
	touch $@

$(OUT)/li0ard_sigs.txt: $(OUT)/cases.txt li0ard/check.mjs li0ard/node_modules
	$(BUN) li0ard/check.mjs $(OUT)/cases.txt $@

# jkurwa і gost89 ставляться точно за bun.lock
jkurwa/node_modules: jkurwa/package.json jkurwa/bun.lock
	cd jkurwa && $(BUN) install --frozen-lockfile
	touch $@

# Конверти (CMS EnvelopedData): jkurwa розкриває конверти uacrypto і шле вміст назад, uacrypto розкриває відповіді
envelope: main.go envelope.go jkurwa/envelope.mjs jkurwa/node_modules $(wildcard ../*/*.go)
	mkdir -p $(OUT)
	go run . envelope-gen $(OUT)/go_env.txt
	$(BUN) jkurwa/envelope.mjs $(OUT)/go_env.txt $(OUT)/jkurwa_env.txt
	go run . envelope-check $(OUT)/go_env.txt $(OUT)/jkurwa_env.txt

$(OUT)/jkurwa_sigs.txt: $(OUT)/cases.txt jkurwa/check.mjs jkurwa/node_modules
	$(BUN) jkurwa/check.mjs $(OUT)/cases.txt $@

tsa: cms $(OUT)/CACertificates.p7b
	cargo run --release --locked -q --manifest-path rust/Cargo.toml -- cades-t $(TSA_URL) $(OUT)/rust_t.txt
	go run . tsa $(TSA_URL) $(OUT)/rust_cms.txt $(OUT)/rust_t.txt $(OUT)/go_t.txt
	cargo run --release --locked -q --manifest-path rust/Cargo.toml -- cms-verify $(OUT)/go_t.txt $(OUT)/CACertificates.p7b

$(OUT)/CACertificates.p7b:
	mkdir -p $(OUT)
	curl -fsSL -o $@.tmp $(CZO_URL)
	echo "$(CZO_SHA256)  $@.tmp" | shasum -a 256 -c - || { echo "пакет ЦЗО оновився: перевірте його і змініть CZO_SHA256"; exit 1; }
	mv $@.tmp $@

czo: $(OUT)/CACertificates.p7b
	go run . czo $<

# Окремий модуль із cgo: основний модуль лишається без cgo. Бібліотека ІІТ поруч із своїми модулями
# (osi, cspe, …), без ключів і без osplm.ini.
iit:
	@test -n "$(IIT_LIB)" || { echo "вкажіть IIT_LIB=/шлях/до/euscp.dylib (або euscp.so)"; exit 1; }
	mkdir -p $(OUT)
	cd iit && go build -o ../$(OUT)/iit .
	$(OUT)/iit $(IIT_LIB)

$(CRYPTONITE_SRC):
	mkdir -p $(OUT)
	curl -fsSL -o $(OUT)/cryptonite.tar.gz.tmp $(CRYPTONITE_URL)
	echo "$(CRYPTONITE_SHA256)  $(OUT)/cryptonite.tar.gz.tmp" | shasum -a 256 -c -
	tar -xzf $(OUT)/cryptonite.tar.gz.tmp -C $(OUT)
	rm $(OUT)/cryptonite.tar.gz.tmp

# Генератор ДСТУ 4145 (PRNG_MODE_DSTU): cryptonite з годинником, підставленим замість time(NULL), друкує
# таблицю випадків; вона має збігтися з ../dstu4145/testdata/cryptonite_prng.txt, на якій uacrypto перевіряє NewPRNG
cryptonite: $(CRYPTONITE_SRC) cryptonite/prng.c
	sed 's/return (uint64_t)time(NULL);/{ extern uint64_t fake_time; return fake_time; }/' \
		$(CRYPTONITE_SRC)/dstu4145_prng_internal.c > $(OUT)/cryptonite_prng_internal.c
	grep -q fake_time $(OUT)/cryptonite_prng_internal.c
	$(CC) -w -DCRYPTONITE_EXPORT= -I$(CRYPTONITE_SRC) -I$(CRYPTONITE_SRC)/../../pthread/c -o $(OUT)/cryptonite_prng cryptonite/prng.c \
		$(OUT)/cryptonite_prng_internal.c $(addprefix $(CRYPTONITE_SRC)/,prng.c gost28147.c gost34_311.c \
		byte_array.c byte_array_internal.c byte_utils_internal.c stacktrace.c word_internal.c math_int_internal.c math_gfp_internal.c rs.c) \
		$(CRYPTONITE_SRC)/../../pthread/c/pthread_impl.c
	$(OUT)/cryptonite_prng > $(OUT)/cryptonite_prng.txt
	cmp $(OUT)/cryptonite_prng.txt ../dstu4145/testdata/cryptonite_prng.txt
	go test -count=1 -run TestPRNGCryptonite ../dstu4145

$(UAPKIC_SRC):
	mkdir -p $(OUT)
	curl -fsSL -o $(OUT)/uapki.tar.gz.tmp $(UAPKI_URL)
	echo "$(UAPKI_SHA256)  $(OUT)/uapki.tar.gz.tmp" | shasum -a 256 -c -
	tar -xzf $(OUT)/uapki.tar.gz.tmp -C $(OUT)
	rm $(OUT)/uapki.tar.gz.tmp

$(UAPKIC_LIB): $(UAPKIC_SRC)
	$(CMAKE) -S $(UAPKIC_SRC) -B $(OUT)/uapkic-build -DUAPKI_LIBS_TYPE=STATIC -DUAPKI_DISABLE_COPY=ON
	$(CMAKE) --build $(OUT)/uapkic-build

# UAPKI — сертифікований форк cryptonite: ГОСТ 34.311, Купина, ГОСТ 28147 (блок, CFB, імітовставка), Калина
# і ДСТУ 4145 в обидва боки
uapki: $(OUT)/cases.txt $(UAPKIC_LIB) uapki/check.c
	$(CC) -std=c99 -D_POSIX_C_SOURCE=200809L -O2 -I$(UAPKIC_SRC)/include -o $(OUT)/uapki_check uapki/check.c $(UAPKIC_LIB) -lpthread
	$(OUT)/uapki_check $(OUT)/cases.txt $(OUT)/uapki_sigs.txt
	go run . verify $(OUT)/uapki_sigs.txt

clean:
	rm -rf $(OUT) rust/target jkurwa/node_modules li0ard/node_modules
