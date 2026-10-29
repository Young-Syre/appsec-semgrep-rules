// Fixtures for non-constant-time-secret-compare.
//
// These stand in for a webhook receiver and a token-authenticated admin route:
// both compute an expected value and compare it to one supplied by the caller.
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

var ErrBadSignature = errors.New("bad signature")

const adminToken = "s3cr3t"

func verifyHexSignature(body []byte, key []byte, providedSig string) bool {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	expectedSig := hex.EncodeToString(m.Sum(nil))
	// ruleid: non-constant-time-secret-compare
	return expectedSig == providedSig
}

func verifyRawMAC(body, key, providedMAC []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	expectedMAC := m.Sum(nil)
	// ruleid: non-constant-time-secret-compare
	return bytes.Equal(expectedMAC, providedMAC)
}

// A long-lived bearer token is the serious case: recovery is total.
func authorize(r *http.Request) bool {
	suppliedToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// ruleid: non-constant-time-secret-compare
	return suppliedToken != adminToken
}

func checkAPIKey(providedAPIKey, storedAPIKey string) bool {
	// ruleid: non-constant-time-secret-compare
	return strings.EqualFold(providedAPIKey, storedAPIKey)
}

func verifyRawMACSafely(body, key, providedMAC []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	// ok: non-constant-time-secret-compare
	return hmac.Equal(m.Sum(nil), providedMAC)
}

func verifyHexSignatureSafely(body, key []byte, providedSig string) bool {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	expectedSig := hex.EncodeToString(m.Sum(nil))
	// ok: non-constant-time-secret-compare
	return subtle.ConstantTimeCompare([]byte(expectedSig), []byte(providedSig)) == 1
}

// A length check is not a content comparison and leaks nothing useful.
func wellFormedSignature(providedSig []byte) bool {
	// ok: non-constant-time-secret-compare
	return len(providedSig) != sha256.Size
}

// Comparing sentinel errors is not a secret comparison, even though the error
// variable is named after a signature.
func isBadSignature(err error) bool {
	// ok: non-constant-time-secret-compare
	return err == ErrBadSignature
}

// A presence check against the zero value leaks only whether a value was sent.
func signaturePresent(providedSig string) bool {
	// ok: non-constant-time-secret-compare
	return providedSig == ""
}
