package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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
	matchString := flag.String("match", "alert(1), confirm(1), prompt(1)", "The string(s) to match against the domain response. Separate multiple strings with commas. (required)")
	onlyVulnerable := flag.Bool("vuln", false, "If set, only vulnerable URLs will be printed.")
	timeout := flag.Int("timeout", 15, "Timeout for HTTP requests in seconds.")
	outputFile := flag.String("o", "", "File to save the output.")
	threads := flag.Int("t", 20, "Number of concurrent threads.")
	userAgent := flag.String("H", "XSSChecker/1.0", "Custom User-Agent header for HTTP requests.")
	verbose := flag.Bool("v", false, "Enable verbose output for debugging purposes.")
	retries := flag.Int("retries", 3, "Number of retry attempts for failed HTTP requests.")
	proxy := flag.String("proxy", "", "Proxy server for HTTP requests.")
	inputFile := flag.String("i", "", "Input file containing list of URLs.")
	singleURL := flag.String("u", "", "Single URL to test.")
	skipStatusCodes := flag.String("ssc", "", "Comma-separated status codes to skip all URLs from a domain if encountered (e.g., 403,500).")
	maxStatusCodeSkips := flag.Int("maxssc", 2, "Maximum number of status code responses required before skipping all URLs from that domain.")
	skipServer := flag.String("scdn", "", "Server name to skip all URLs for (e.g., cloudflare).")

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
	skipStatusCodeList := make(map[int]bool)
	if *skipStatusCodes != "" {
		for _, codeStr := range strings.Split(*skipStatusCodes, ",") {
			code, err := strconv.Atoi(codeStr)
			if err != nil {
				fmt.Printf("Invalid status code: %s\n", codeStr)
				return
			}
			skipStatusCodeList[code] = true
		}
	}

	sc := bufio.NewScanner(os.Stdin)

	if *inputFile != "" {
		file, err := os.Open(*inputFile)
		if err != nil {
			fmt.Println("Error opening input file:", err)
			return
		}
		defer file.Close()
		sc = bufio.NewScanner(file)
	}

	jobs := make(chan string)
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
	}

	// Set proxy if provided
	if *proxy != "" {
		proxyURL, err := url.Parse(*proxy)
		if err != nil {
			fmt.Println("Error parsing proxy URL:", err)
			return
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	// Create output file if specified
	var output *os.File
	if *outputFile != "" {
		output, err = os.Create(*outputFile)
		if err != nil {
			fmt.Println("Error creating output file:", err)
			return
		}
		defer output.Close()
	}

	skippedDomains := make(map[string]int)
	skippedDomainsLimitReached := make(map[string]bool)
	var skippedDomainsLock sync.Mutex

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				urlParsed, err := url.Parse(domain)
				if err != nil {
					if *verbose {
						fmt.Println("Error parsing URL:", err)
					}
					continue
				}
				host := urlParsed.Host

				// Check if the domain should be skipped
				skippedDomainsLock.Lock()
				if skippedDomainsLimitReached[host] {
					skippedDomainsLock.Unlock()
					continue
				}
				skippedDomainsLock.Unlock()

				for attempt := 0; attempt < *retries; attempt++ {
					req, err := http.NewRequest("GET", domain, nil)
					if err != nil {
						if *verbose {
							fmt.Println("Error creating request:", err)
						}
						continue
					}
					req.Header.Set("User-Agent", *userAgent)

					resp, err := client.Do(req)
					if err != nil {
						if *verbose {
							fmt.Println("Error making request:", err)
						}
						continue
					}
					defer resp.Body.Close()

					body, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						if *verbose {
							fmt.Println("Error reading response body:", err)
						}
						continue
					}
					sb := string(body)

					isVulnerable := false
					for _, str := range matchStrings {
						if strings.Contains(sb, str) {
							isVulnerable = true
							break
						}
					}

					status := fmt.Sprintf("[%d] ", resp.StatusCode)
					server := resp.Header.Get("Server")
					outputStr := ""
					if isVulnerable {
						outputStr = fmt.Sprintf("\033[1;31mVulnerable: %s[%s] %s\033[0;0m\n", status, server, domain)
					} else if !*onlyVulnerable { // If onlyVulnerable is false, print non-vulnerable URLs
						outputStr = fmt.Sprintf("\033[1;35mNot Vulnerable: %s[%s] %s\033[0;0m\n", status, server, domain)
					}

					fmt.Print(outputStr)
					if output != nil {
						output.WriteString(outputStr)
					}

					// Check if the response meets the skip criteria
					if *skipStatusCodes != "" && skipStatusCodeList[resp.StatusCode] && strings.Contains(strings.ToLower(server), strings.ToLower(*skipServer)) {
						skippedDomainsLock.Lock()
						skippedDomains[host]++
						if skippedDomains[host] >= *maxStatusCodeSkips {
							skippedDomainsLimitReached[host] = true
							fmt.Printf("Skipped all URLs of this domain %s [ERR: Blocked by %s]\n", host, *skipServer)
						}
						skippedDomainsLock.Unlock()
						break // Exit retry loop on skip condition met
					}
					break // Exit retry loop on successful request
				}
			}
		}()
	}

	// Handle single URL input
	if *singleURL != "" {
		jobs <- *singleURL
	} else {
		// Handle multiple URLs from input
		for sc.Scan() {
			domain := sc.Text()
			jobs <- domain
		}
	}

	close(jobs)
	wg.Wait()
}
