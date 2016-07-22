package gpgme

// #cgo CFLAGS: -DISCGO=1 -I/usr/local/include -I/usr/include -Wall
// #cgo CPPFLAGS: -DISCGO=1 -I/usr/local/include -I/usr/include
// #cgo LDFLAGS: -L/usr/local/lib -L/usr/lib -lgpg-error -lassuan -lgpgme
// #include <stdlib.h>
// #include "gpgme-bridge.h"
import "C"
import (
	"errors"
	"sync"
	"time"
	"unsafe"
)

var (
	FailedEncryptionError = errors.New("Failed to encrypt message.")
	FailedDecryptionError = errors.New("Failed to decrypt message.")
	InvalidKeyError       = errors.New("Provided public key is invalid. Please make sure the key has not expired or revoked.")
	MissingEmailError     = errors.New("Public key must contain a valid email address.")

	importPublicKeyLock = &sync.Mutex{}
	encryptLock         = &sync.Mutex{}
	decryptLock         = &sync.Mutex{}
)

type KeyInfo interface {
	Fingerprint() string
	ExpiresAt() time.Time
	Email() string
	Name() string
	Comment() string
}

type keyInfo struct {
	fingerprint string
	expiresAt   time.Time
	email       string
	name        string
	comment     string
}

func (k keyInfo) Fingerprint() string {
	return k.fingerprint
}

func (k keyInfo) ExpiresAt() time.Time {
	return k.expiresAt
}

func (k keyInfo) Email() string {
	return k.email
}

func (k keyInfo) Name() string {
	return k.name
}

func (k keyInfo) Comment() string {
	return k.comment
}

func ImportPublicKey(s string) (KeyInfo, error) {
	// Get a keyInfo object
	var cKeyInfo *C.struct_key_info = C.new_key_info()
	// Free keyData since we use CString to allocate it
	defer C.free_key_info(cKeyInfo)

	// Convert passed in public key to a C char array
	keyData := C.CString(s)
	defer C.free(unsafe.Pointer(keyData))

	// Now perform the import by protecting with a lock
	importPublicKeyLock.Lock()
	C.import_key(cKeyInfo, keyData)
	importPublicKeyLock.Unlock()

	// Handle key info
	ki := keyInfo{}

	// fingerprint is a character array
	fingerprint := C.GoStringN(&cKeyInfo.fingerprint[0], C.KEY_FINGERPRINT_LEN)
	if fingerprint == "" {
		return nil, InvalidKeyError
	}
	ki.fingerprint = fingerprint

	if cKeyInfo.expires > 0 {
		ki.expiresAt = time.Unix(int64(cKeyInfo.expires), 0)
	}

	// Now handle the user info

	emailLen := C.int(C.strlen(&cKeyInfo.user_email[0]))
	nameLen := C.int(C.strlen(&cKeyInfo.user_name[0]))
	commentLen := C.int(C.strlen(&cKeyInfo.user_comment[0]))

	if emailLen == 0 {
		return nil, MissingEmailError
	}

	email := C.GoStringN(&cKeyInfo.user_email[0], emailLen)
	if email == "" {
		return nil, MissingEmailError
	}
	ki.email = email
	ki.name = C.GoStringN(&cKeyInfo.user_name[0], nameLen)
	ki.comment = C.GoStringN(&cKeyInfo.user_comment[0], commentLen)

	return ki, nil
}

func EncryptMessage(message, fingerprint string) (string, error) {
	// Get the fingerprint as a C string
	fpr := C.CString(fingerprint)
	defer C.free(unsafe.Pointer(fpr))

	// Get message as a C string
	msg := C.CString(message)
	defer C.free(unsafe.Pointer(msg))

	// Call into C to encrypt
	encryptLock.Lock()
	cipher := C.encrypt(fpr, msg)
	encryptLock.Unlock()
	if cipher == nil {
		return "", FailedEncryptionError
	}
	defer C.free(unsafe.Pointer(cipher))

	output := C.GoString(cipher)
	if output == "" {
		return "", FailedEncryptionError
	}

	return output, nil
}

func DecryptMessage(encryptedMessage string) (string, error) {
	// Get message as a C string
	msg := C.CString(encryptedMessage)
	defer C.free(unsafe.Pointer(msg))

	// Call into C to encrypt
	decryptLock.Lock()
	decryptedMessage := C.decrypt(msg)
	decryptLock.Unlock()
	if decryptedMessage == nil {
		return "", FailedDecryptionError
	}
	defer C.free(unsafe.Pointer(decryptedMessage))

	output := C.GoString(decryptedMessage)
	if output == "" {
		return "", FailedDecryptionError
	}

	return output, nil
}
