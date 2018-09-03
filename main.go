package main

import (
	"bytes"
	"fmt"
	"encoding/json"
	"log"
	"os"
	"os/user"
	"path"
)

var (
	AWSCredsVaultBaseDir = ".aws/creds-vault"
)

func getVaultFile(p string) string {
	d := getVaultDir()
	r := path.Join(d, p)

	return r
}

func getVaultDir() string {
	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	p := path.Join(u.HomeDir, AWSCredsVaultBaseDir)

	return p
}

func getProfile() string {
	if len(os.Args) == 2 {
		return os.Args[1]
	}
	if pr := os.Getenv("AWS_PROFILE"); len(pr) != 0 {
		return pr
	}
	if dpr := os.Getenv("AWS_DEFAULT_PROFILE"); len(dpr) != 0 {
		return dpr
	}

	return ""
}

func main() {
	awsProfile := getProfile()

	var buf bytes.Buffer
	gpg, err := NewGPGCommander()
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Open(getVaultFile(awsProfile))
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}
	cnf := &GPGCommandConfig{}
	cnf.Stdin = f
	
	gpg.Decrypt(&buf, cnf)
	creds := AWSCredentials{}
	json.Unmarshal(buf.Bytes(), &creds)
	fmt.Print(creds.String())
}
