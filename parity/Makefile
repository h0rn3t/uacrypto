# Звірка uacrypto з Bouncy Castle (Java) і Rust-бібліотеками. Потрібні go, java/javac, cargo, curl.
#   make          — уся звірка; ненульовий код виходу, якщо хоч щось розійшлося
#   make czo      — перевірити підписи всіх ДСТУ-сертифікатів пакета ЦЗО (окремо: пакет оновлюється)
#   make clean    — прибрати згенероване

BC_VERSION := 1.86
BC_JAR     := java/bcprov-jdk18on-$(BC_VERSION).jar
BC_SHA256  := 2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f
BC_URL     := https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/$(BC_VERSION)/bcprov-jdk18on-$(BC_VERSION).jar
CZO_URL    := https://czo.gov.ua/download/certificates/CACertificates.p7b
CZO_SHA256 := efc6a4ecf5ca10dd099335fbf2c1173d597110b4eb431cb89652e7b7369029c4
OUT        := out
JAVA       ?= java
JAVAC      ?= javac

.PHONY: all cms czo clean
all: $(OUT)/cases.txt $(OUT)/bc_sigs.txt $(OUT)/rust_sigs.txt cms
	cat $(OUT)/bc_sigs.txt $(OUT)/rust_sigs.txt > $(OUT)/foreign_sigs.txt
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

$(BC_JAR):
	curl -fsSL -o $@.tmp $(BC_URL)
	echo "$(BC_SHA256)  $@.tmp" | shasum -a 256 -c -
	mv $@.tmp $@

$(OUT)/bc_sigs.txt: $(OUT)/cases.txt $(BC_JAR) java/Check.java
	$(JAVAC) -d $(OUT)/java -cp $(BC_JAR) java/Check.java
	$(JAVA) -cp $(BC_JAR):$(OUT)/java Check $(OUT)/cases.txt $@

$(OUT)/rust_sigs.txt: $(OUT)/cases.txt rust/src/main.rs rust/Cargo.toml rust/Cargo.lock
	cargo run --release --locked -q --manifest-path rust/Cargo.toml -- $(OUT)/cases.txt $@

$(OUT)/CACertificates.p7b:
	mkdir -p $(OUT)
	curl -fsSL -o $@.tmp $(CZO_URL)
	echo "$(CZO_SHA256)  $@.tmp" | shasum -a 256 -c - || { echo "пакет ЦЗО оновився: перевірте його і змініть CZO_SHA256"; exit 1; }
	mv $@.tmp $@

czo: $(OUT)/CACertificates.p7b
	go run . czo $<

clean:
	rm -rf $(OUT) rust/target $(BC_JAR)
