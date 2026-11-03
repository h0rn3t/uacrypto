# Звірка uacrypto з Bouncy Castle (Java) і Rust-бібліотеками. Потрібні go, java/javac, cargo, curl.
#   make          — уся звірка; ненульовий код виходу, якщо хоч щось розійшлося
#   make clean    — прибрати згенероване

BC_VERSION := 1.86
BC_JAR     := java/bcprov-jdk18on-$(BC_VERSION).jar
BC_SHA256  := 2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f
BC_URL     := https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/$(BC_VERSION)/bcprov-jdk18on-$(BC_VERSION).jar
OUT        := out
JAVA       ?= java
JAVAC      ?= javac

.PHONY: all clean
all: $(OUT)/cases.txt $(OUT)/bc_sigs.txt $(OUT)/rust_sigs.txt
	cat $(OUT)/bc_sigs.txt $(OUT)/rust_sigs.txt > $(OUT)/foreign_sigs.txt
	go run . verify $(OUT)/foreign_sigs.txt

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

clean:
	rm -rf $(OUT) rust/target $(BC_JAR)
