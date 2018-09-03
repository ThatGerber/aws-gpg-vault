package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
)

var defaultLogFilePath = ".aws/creds-vault/vault.log"

func main() {
	var appLog *os.File

	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	lgFilePath := path.Join(u.HomeDir, defaultLogFilePath)

	profile, err := getAWSProfile()
	if err != nil {
		log.Fatal(err)
	}

	vaultFile, err := GetVaultFile(profile)
	if err != nil {
		log.Fatal(err)
	}

	var buf bytes.Buffer
	cnf := &GPGCommandConfig{}
	cnf.Stdin = vaultFile
	cnf.Stdout = vaultFile
	cnf.Stderr = &buf

	gpg, err := NewGPGCommander(cnf)
	if err != nil {
		log.Fatal(err)
	}

	gpg.Decrypt(nil, cnf)

	appLog, err = os.OpenFile(lgFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(appLog)
	log.Print(buf.String())

	fmt.Printf("%s", vaultFile.Credentials)
}
