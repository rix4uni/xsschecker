package main

import (
	"sync"
	"bufio"
	"net/http"
	"fmt"
	"os"
	"strings"
	"io/ioutil"
)

func main(){

	colorReset := "\033[0m"
	colorRed := "\033[31m"
	colorGreen := "\033[32m"

	const banner = `
 _  _  ___  ___   ___  _   _  ____  ___  _  _  ____  ____ 
( \/ )/ __)/ __) / __)( )_( )( ___)/ __)( )/ )( ___)(  _ \
 )  ( \__ \\__ \( (__  ) _ (  )__)( (__  )  (  )__)  )   /
(_/\_)(___/(___/ \___)(_) (_)(____)\___)(_)\_)(____)(_)\_)
v0.1 				coded by @rix4uni in INDIA
`

	fmt.Println(colorGreen,banner,colorReset)


	sc := bufio.NewScanner(os.Stdin)

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i:= 0; i < 20; i++{

		wg.Add(1)
		go func(){
			defer wg.Done()
			for domain := range jobs {

				resp, err := http.Get(domain)
				if err != nil{
					continue
				}
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
	      			fmt.Println(err)
	   			}
	   			sb := string(body)
	   			check_result1 := strings.Contains(sb , "prompt(1)")
	   			check_result2 := strings.Contains(sb , "confirm(1)")
	   			check_result3 := strings.Contains(sb , "alert(1)")
	   			
	   			if check_result1 != false {
	   				fmt.Println(string(colorRed),"Vulnerable To XSS:", domain,string(colorReset))
	   			}else if check_result2 != false {
	   				fmt.Println(string(colorRed),"Vulnerable To XSS:", domain,string(colorReset))
	   			}else if check_result3 != false {
	   				fmt.Println(string(colorRed),"Vulnerable To XSS:", domain,string(colorReset))
				}else {
					fmt.Println(string(colorGreen),"Not Vulnerable To XSS:", domain, string(colorReset))
				}
			}
			
   		}()

	}



	for sc.Scan(){
		domain := sc.Text()
		jobs <- domain		
		

	}
	close(jobs)
	wg.Wait()
}
