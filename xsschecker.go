package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
)

func main() {

	// Define the flags
	matchString := flag.String("match", "", "String to match against the domain response")
	onlyVulnerable := flag.Bool("vuln", false, "Print only vulnerable URLs if set")
	flag.Parse()

	if *matchString == "" {
		fmt.Println("Please provide a match string using the -match flag.")
		return
	}

	sc := bufio.NewScanner(os.Stdin)

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {

		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {

				resp, err := http.Get(domain)
				if err != nil {
					continue
				}
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println(err)
				}
				sb := string(body)

				isVulnerable := strings.Contains(sb, *matchString)

				if isVulnerable {
					fmt.Println("\033[1;31mVulnerable: " + domain + "\033[0;0m")
				} else if !*onlyVulnerable { // If onlyVulnerable is false, print non-vulnerable URLs
					fmt.Println("\033[1;35mNot Vulnerable: " + domain + "\033[0;0m")
				}
			}
		}()
	}

	for sc.Scan() {
		domain := sc.Text()
		jobs <- domain
	}
	close(jobs)
	wg.Wait()
}
