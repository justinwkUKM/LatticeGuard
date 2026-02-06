package main

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/md5"
	"fmt"
)

func main() {
	// 1. RSA Key Gen
	reader := rand.Reader
	bitSize := 2048
	key, _ := rsa.GenerateKey(reader, bitSize)
	fmt.Println("Key generated:", key)

	// 2. Weak Hash
	h := md5.New()
	h.Write([]byte("some data"))
	fmt.Printf("%x\n", h.Sum(nil))
}
