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

const version = "0.0.5"

func printUsage() {
	fmt.Println("Usage: xsschecker [OPTIONS]")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
}

func printVersion() {
	fmt.Printf("xsschecker version %s\n", version)
}

func main() {
	// Suppress the default error output of the flag package
	flag.CommandLine.Usage = func() {}

	// Define the flags with clearer descriptions
	versionFlag := flag.Bool("version", false, "Print the version of the tool and exit.")
	matchString := flag.String("match", "alert(1), confirm(1), prompt(1)", "The string(s) to match against the domain response. Separate multiple strings with commas. (required)")
	onlyVulnerable := flag.Bool("vuln", false, "If set, only vulnerable URLs will be printed.")
	filter := flag.Bool("filter", false, "Print only URLs Exclude this from output, (e.g. Vulnerable/Not Vulnerable: [status] [server]).")
	timeout := flag.Int("timeout", 15, "Timeout for HTTP requests in seconds.")
	outputFile := flag.String("o", "", "File to save the output.")
	appendOutput := flag.String("ao", "", "File to append the output instead of overwriting.")
	noColor := flag.Bool("nc", false, "Do not use colored output.")
	threads := flag.Int("t", 20, "Number of concurrent threads.")
	userAgent := flag.String("H", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", "Custom User-Agent header for HTTP requests.")
	verbose := flag.Bool("v", false, "Enable verbose output for debugging purposes.")
	retries := flag.Int("retries", 1, "Number of retry attempts for failed HTTP requests.")
	proxy := flag.String("proxy", "", "Proxy server for HTTP requests. (e.g., http://127.0.0.1:8080)")
	inputFile := flag.String("i", "", "Input file containing list of URLs.")
	singleURL := flag.String("u", "", "Single URL to test.")
	skipStatusCodes := flag.String("ssc", "", "Comma-separated status codes to skip all URLs from a domain if encountered (e.g., 403,400).")
	maxStatusCodeSkips := flag.Int("maxssc", 20, "Maximum number of status code responses required before skipping all URLs from that domain, This flag only can be use with -ssc flag.")
	skipServer := flag.String("scdn", "", "Comma-separated server names to skip all URLs for (e.g., \"cloudflare,AkamaiGHost,CloudFront,Imperva\").")

	// Custom flag parsing to handle unknown flags
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	err := flag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		printUsage()
		return
	}

	// Print version and exit if --version flag is provided
	if *versionFlag {
		printVersion()
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

	// Parse the skip server names into a slice
	skipServers := strings.Split(*skipServer, ",")

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

	// Create or open output file if specified
	var output *os.File
	if *outputFile != "" {
		output, err = os.Create(*outputFile)
		if err != nil {
			fmt.Println("Error creating output file:", err)
			return
		}
		defer output.Close()
	} else if *appendOutput != "" {
		output, err = os.OpenFile(*appendOutput, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Println("Error opening output file for appending:", err)
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
						if *noColor {
							if *filter {
								outputStr = fmt.Sprintf("%s\n", domain)
							} else {
								outputStr = fmt.Sprintf("Vulnerable: %s[%s] %s\n", status, server, domain)
							}
						} else {
							if *filter {
								outputStr = fmt.Sprintf("\033[1;31m%s\033[0;0m\n", domain)
							} else {
								outputStr = fmt.Sprintf("\033[1;31mVulnerable: %s[%s] %s\033[0;0m\n", status, server, domain)
							}
						}
					} else if !*onlyVulnerable { // If onlyVulnerable is false, print non-vulnerable URLs
						if *noColor {
							if *filter {
								outputStr = fmt.Sprintf("%s\n", domain)
							} else {
								outputStr = fmt.Sprintf("Not Vulnerable: %s[%s] %s\n", status, server, domain)
							}
						} else {
							if *filter {
								outputStr = fmt.Sprintf("\033[1;35m%s\033[0;0m\n", domain)
							} else {
								outputStr = fmt.Sprintf("\033[1;35mNot Vulnerable: %s[%s] %s\033[0;0m\n", status, server, domain)
							}
						}
					}

					fmt.Print(outputStr)
					if output != nil {
						output.WriteString(outputStr)
					}

					// Check if the response meets the skip criteria
					if *skipStatusCodes != "" {
						for _, skipServerName := range skipServers {
							if skipStatusCodeList[resp.StatusCode] && strings.Contains(strings.ToLower(server), strings.ToLower(skipServerName)) {
								skippedDomainsLock.Lock()
								skippedDomains[host]++
								if skippedDomains[host] >= *maxStatusCodeSkips {
									skippedDomainsLimitReached[host] = true
									if *verbose {
										fmt.Printf("Skipped all URLs of this domain %s [ERR: Blocked by %s]\n", host, *skipServer)
									}
								}
								skippedDomainsLock.Unlock()
								break // Exit retry loop on skip condition met
							}
						}
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
