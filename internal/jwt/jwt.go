// Package jwt provides the JWT primitives: parsing (Parse/Token), base64url
// encoding, HMAC (HS256/384/512) and RSA (RS256) signing, and exporting an RSA
// public key as a JWK.
package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

type Token struct {
	Header  map[string]any
	Payload map[string]any
	Parts   []string
}

func Parse(raw string) (*Token, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	decodeHeader, err := DecodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %w", err)
	}
	decodeBody, err := DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid body encoding: %w", err)
	}
	var header map[string]any
	err = json.Unmarshal(decodeHeader, &header)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var body map[string]any
	err = json.Unmarshal(decodeBody, &body)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	t := Token{
		Header:  header,
		Payload: body,
		Parts:   parts,
	}
	return &t, nil
}

func DecodeBase64URL(part string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return data, nil
}

func SignHMAC(part0 string, part1 string, key string, alg string) (string, error) {
	var newHash func() hash.Hash
	switch alg {
	case "HS256":
		newHash = sha256.New
	case "HS384":
		newHash = sha512.New384
	case "HS512":
		newHash = sha512.New
	default:
		return "", fmt.Errorf("unsupported HMAC algorithm %s", alg)
	}
	// calculating signature to check the key
	signingInput := part0 + "." + part1
	mac := hmac.New(newHash, []byte(key))
	mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func SignRSA(part0, part1 string, priv *rsa.PrivateKey) (string, error) {
	signingInput := part0 + "." + part1
	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("rsa sign: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func PublicKeyToJWK(pub *rsa.PublicKey) map[string]any {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return map[string]any{
		"kty": "RSA",
		"n":   n,
		"e":   e,
	}
}

func EncodeSegment(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("json marshal: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
