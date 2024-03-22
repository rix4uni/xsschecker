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

func printUsage() {
	fmt.Println("Usage: xsschecker [OPTIONS]")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
}

func main() {

	// Suppress the default error output of the flag package
	flag.CommandLine.Usage = func() {}

	// Define the flags with clearer descriptions
	matchString := flag.String("match", "", "The string(s) to match against the domain response. Separate multiple strings with commas. (required)")
	onlyVulnerable := flag.Bool("vuln", false, "If set, only vulnerable URLs will be printed.")

	// Custom flag parsing to handle unknown flags
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	err := flag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		printUsage()
		return
	}

	// If no flags are provided or required flags are missing, print usage and exit.
	if len(os.Args) == 1 {
		printUsage()
		return
	}

	if *matchString == "" {
		fmt.Println("Please provide a match string using the -match flag.")
		return
	}

	matchStrings := strings.Split(*matchString, ", ")

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

				isVulnerable := false
				for _, str := range matchStrings {
					if strings.Contains(sb, str) {
						isVulnerable = true
						break
					}
				}

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
