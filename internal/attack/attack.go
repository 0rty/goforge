// Package attack gathers the active attacks on JWT. For now: the parallelized
// bruteforce of the HMAC key (BruteforceKey).
package attack

import (
	"bufio"
	"context"
	"crypto/hmac"
	"fmt"
	"goforge/internal/jwt"
	"os"
	"sync"
)

// BruteforceKey tests each word of the wordlist as the HMAC key (algorithm alg),
// in parallel over `workers` goroutines, stopping as soon as a key reproduces the
// token signature. Returns the found key, "" if none, or an I/O error.
func BruteforceKey(parts []string, wordlist string, workers int, alg string) (string, error) {
	file, err := os.Open(wordlist)
	if err != nil {
		return "", fmt.Errorf("open wordlist: %w", err)
	}
	defer file.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	words := make(chan string) // channel for words to test
	result := make(chan string, 1)
	var wg sync.WaitGroup
	var readErr error

	// starting N workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done(): // finish the task if the word is found
					return
				case word, ok := <-words: // receiving a word from the wordlist
					if !ok {
						return
					}
					candidate, err := jwt.SignHMAC(parts[0], parts[1], word, alg)
					if err != nil {
						cancel()
						return
					}
					if hmac.Equal([]byte(candidate), []byte(parts[2])) {
						result <- word
						cancel()
						return

					}
				}
			}
		}()
	}

	// read the wordlist and feed 'words'
	go func() {
		// read line by line
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			case words <- scanner.Text():
			}
		}
		readErr = scanner.Err()
		close(words) // close the channel when no more words
	}()

	go func() {
		wg.Wait()
		close(result)
	}()

	key := <-result
	if key == "" {
		if readErr != nil {
			return "", fmt.Errorf("read wordlist: %w", readErr)
		}
	}
	return key, nil
}
