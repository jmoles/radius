package main

import (
	"log"

	"github.com/jmoles/radius/radius"
)

func main() {
	s := new(radius.Server)
	s.Secret = "testsecret"
	log.Fatal(s.ListenAndServe())
}
