package main

import (
	"io/ioutil"
	"log"
	"./scan"
)

func init() {
	log.SetOutput(ioutil.Discard)
}

func main() {
	scan.FromStdin()
}
