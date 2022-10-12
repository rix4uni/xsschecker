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
	   				fmt.Println("\033[1;31mVulnerable: "+domain+"\033[0;0m")
	   			}else if check_result2 != false {
	   				fmt.Println("\033[1;31mVulnerable: "+domain+"\033[0;0m")
	   			}else if check_result3 != false {
	   				fmt.Println("\033[1;31mVulnerable: "+domain+"\033[0;0m")
				}else {
					fmt.Println("\033[1;30mNot Vulnerable: "+domain+"\033[0;0m")
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
