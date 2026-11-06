package main

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>

// The EU Sign entry points the checks call, as the library documents them.
// Every one that returns a code returns 0 on success.
typedef unsigned long (*euInitialize)(void);
typedef unsigned long (*euCtxCreate)(void **ctx);
typedef unsigned long (*euCtxHashData)(void *ctx, unsigned long algo,
	unsigned char *cert, unsigned long certLen,
	unsigned char *data, unsigned long dataLen,
	unsigned char **hash, unsigned long *hashLen);
typedef void (*euCtxFreeMemory)(void *ctx, unsigned char *p);
typedef unsigned long (*euAlgoCtxCreate)(unsigned long algo, void **ctx);
typedef unsigned long (*euAlgoCtxSetKey)(void *ctx,
	unsigned char *key, unsigned long keyLen, unsigned char *iv, unsigned long ivLen);
typedef unsigned long (*euAlgoCtxEncrypt)(void *ctx, unsigned char *data, unsigned long dataLen);
typedef unsigned long (*euAlgoCtxGetDataMAC)(void *ctx,
	unsigned char *data, unsigned long dataLen, unsigned char *mac, unsigned long macLen);
typedef void (*euAlgoCtxFree)(void *ctx);
typedef char *(*euGetErrorLangDesc)(unsigned long code, unsigned long lang);

// The library loads its modules from its own directory, and they look its
// symbols up, so the symbols stay global.
static void *library_open(const char *path) { return dlopen(path, RTLD_NOW | RTLD_GLOBAL); }
static const char *library_error(void) { return dlerror(); }
static void *library_symbol(void *h, const char *name) { return dlsym(h, name); }

static unsigned long eu_initialize(void *f) { return ((euInitialize)f)(); }
static unsigned long eu_ctx_create(void *f, void **ctx) { return ((euCtxCreate)f)(ctx); }
static unsigned long eu_ctx_hash_data(void *f, void *ctx, unsigned long algo,
		unsigned char *data, unsigned long dataLen, unsigned char **hash, unsigned long *hashLen) {
	return ((euCtxHashData)f)(ctx, algo, NULL, 0, data, dataLen, hash, hashLen);
}
static void eu_ctx_free_memory(void *f, void *ctx, unsigned char *p) { ((euCtxFreeMemory)f)(ctx, p); }
static unsigned long eu_algo_create(void *f, unsigned long algo, void **ctx) { return ((euAlgoCtxCreate)f)(algo, ctx); }
static unsigned long eu_algo_set_key(void *f, void *ctx,
		unsigned char *key, unsigned long keyLen, unsigned char *iv, unsigned long ivLen) {
	return ((euAlgoCtxSetKey)f)(ctx, key, keyLen, iv, ivLen);
}
static unsigned long eu_algo_encrypt(void *f, void *ctx, unsigned char *data, unsigned long dataLen) {
	return ((euAlgoCtxEncrypt)f)(ctx, data, dataLen);
}
static unsigned long eu_algo_mac(void *f, void *ctx,
		unsigned char *data, unsigned long dataLen, unsigned char *mac, unsigned long macLen) {
	return ((euAlgoCtxGetDataMAC)f)(ctx, data, dataLen, mac, macLen);
}
static void eu_algo_free(void *f, void *ctx) { ((euAlgoCtxFree)f)(ctx); }
static char *eu_error(void *f, unsigned long code) { return ((euGetErrorLangDesc)f)(code, 3); }
*/
import "C"

import (
	"fmt"
	"slices"
	"unsafe"
)

// The hash and algorithm identifiers of the EU Sign interface.
const (
	hashGOST34311 = 1
	hashKupyna256 = 7
	hashKupyna384 = 8
	hashKupyna512 = 9
	algoKalynaCFB = 1 // DSTU 7624 with a 256-bit block and key, CFB
)

// library is a loaded and initialized EU Sign library with one hashing
// context. It is not safe for concurrent use.
type library struct {
	initialize, ctxCreate, ctxHashData, ctxFreeMemory unsafe.Pointer
	algoCreate, algoSetKey, algoEncrypt, algoMAC      unsafe.Pointer
	algoFree, errorDesc                               unsafe.Pointer
	ctx                                               unsafe.Pointer
}

// openLibrary loads the EU Sign library at path (euscp.dylib, euscp.so) and
// initializes it. The library finds its own modules next to itself.
func openLibrary(path string) (*library, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	h := C.library_open(cPath)
	if h == nil {
		return nil, fmt.Errorf("dlopen %s: %s", path, C.GoString(C.library_error()))
	}

	var missing []string
	symbol := func(name string) unsafe.Pointer {
		cName := C.CString(name)
		defer C.free(unsafe.Pointer(cName))
		p := C.library_symbol(h, cName)
		if p == nil {
			missing = append(missing, name)
		}
		return p
	}
	l := &library{
		initialize:    symbol("EUInitialize"),
		ctxCreate:     symbol("EUCtxCreate"),
		ctxHashData:   symbol("EUCtxHashData"),
		ctxFreeMemory: symbol("EUCtxFreeMemory"),
		algoCreate:    symbol("EUAlgoCtxCreate"),
		algoSetKey:    symbol("EUAlgoCtxSetKey"),
		algoEncrypt:   symbol("EUAlgoCtxEncrypt"),
		algoMAC:       symbol("EUAlgoCtxGetDataMAC"),
		algoFree:      symbol("EUAlgoCtxFree"),
		errorDesc:     symbol("EUGetErrorLangDesc"),
	}
	if missing != nil {
		return nil, fmt.Errorf("%s has no %v", path, missing)
	}
	if err := l.check("EUInitialize", C.eu_initialize(l.initialize)); err != nil {
		return nil, err
	}
	if err := l.check("EUCtxCreate", C.eu_ctx_create(l.ctxCreate, &l.ctx)); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *library) check(op string, code C.ulong) error {
	if code == 0 {
		return nil
	}
	return fmt.Errorf("%s: error %#x: %s", op, uint64(code), C.GoString(C.eu_error(l.errorDesc, code)))
}

// hash returns the digest of data under one of the hash identifiers. With no
// certificate GOST 34.311 uses ДКЕ №1.
func (l *library) hash(algo int, data []byte) ([]byte, error) {
	var out *C.uchar
	var n C.ulong
	code := C.eu_ctx_hash_data(l.ctxHashData, l.ctx, C.ulong(algo), bytesPtr(data), C.ulong(len(data)), &out, &n)
	if err := l.check("EUCtxHashData", code); err != nil {
		return nil, err
	}
	defer C.eu_ctx_free_memory(l.ctxFreeMemory, l.ctx, out)
	return C.GoBytes(unsafe.Pointer(out), C.int(n)), nil
}

// withKalyna runs f on a fresh Kalyna-256 CFB context keyed with key and iv.
func (l *library) withKalyna(key, iv []byte, f func(ctx unsafe.Pointer) C.ulong) error {
	var ctx unsafe.Pointer
	if err := l.check("EUAlgoCtxCreate", C.eu_algo_create(l.algoCreate, algoKalynaCFB, &ctx)); err != nil {
		return err
	}
	defer C.eu_algo_free(l.algoFree, ctx)
	code := C.eu_algo_set_key(l.algoSetKey, ctx, bytesPtr(key), C.ulong(len(key)), bytesPtr(iv), C.ulong(len(iv)))
	if err := l.check("EUAlgoCtxSetKey", code); err != nil {
		return err
	}
	return l.check("EUAlgoCtx", f(ctx))
}

// encryptCFB returns plaintext encrypted with Kalyna-256 in CFB mode.
func (l *library) encryptCFB(key, iv, plaintext []byte) ([]byte, error) {
	out := slices.Clone(plaintext)
	err := l.withKalyna(key, iv, func(ctx unsafe.Pointer) C.ulong {
		return C.eu_algo_encrypt(l.algoEncrypt, ctx, bytesPtr(out), C.ulong(len(out)))
	})
	return out, err
}

// mac returns the Kalyna-256 MAC of data, macSize bytes long.
func (l *library) mac(key, iv, data []byte, macSize int) ([]byte, error) {
	out := make([]byte, macSize)
	err := l.withKalyna(key, iv, func(ctx unsafe.Pointer) C.ulong {
		return C.eu_algo_mac(l.algoMAC, ctx, bytesPtr(data), C.ulong(len(data)), bytesPtr(out), C.ulong(macSize))
	})
	return out, err
}

// bytesPtr passes b to C; an empty input goes as NULL.
func bytesPtr(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}
