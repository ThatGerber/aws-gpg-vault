package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"os/user"
	"path"
	"time"
)

var (
	// AWSCredsVaultBaseDir is the path from the home dir to the encrypted files
	AWSCredsVaultBaseDir = ".aws/creds-vault"
	// AWSCredentialDuration refers to the default amount of time credentials
	// should be valid.
	AWSCredentialDuration = time.Duration(8) * time.Hour
	// ErrVaultFileNotExist is returned when the application is unable to locate
	// a suitable file.
	ErrVaultFileNotExist  = errors.New("unable to find aws-gpg-vault file")
	errAWSProfileNotFound = errors.New("unable to determine AWS config profile")
)

func init() {
	dir := getVaultDir()
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		log.Fatal(err)
	}
}

// AWSCredentials represents a struct with the fields required by the AWS cli
// credential_process.
type AWSCredentials struct {
	Version         int       `json:"Version"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken,omitempty"`
	Expiration      time.Time `json:"Expiration,string,omitempty"`
}

func (a *AWSCredentials) String() string {
	r, err := json.Marshal(a)
	if err != nil {
		log.Fatal(err)
	}

	return string(r)
}

// CredentialVault is an io.ReadWriter. Takes a file path and returns AWS
// credentials.
type CredentialVault struct {
	Path        string
	body        []byte
	cur         int
	Credentials *AWSCredentials
}

// GetVaultFile returns a new vault struct containing path of the intended file.
// It will return an the object and an error (`errVaultFileNotExist`) if the
// targeted file does not exist. If it receives an error of a different type, it
// will return nil and the error.
func GetVaultFile(name string) (*CredentialVault, error) {
	p, err := getVaultFilePath(name)
	if err != nil && err != ErrVaultFileNotExist {
		return nil, err
	}

	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	d := make([]byte, 0)
	j := make([]byte, 1)
	for {
		n, err := f.Read(j)
		if err == io.EOF {
			break
		}
		d = append(d, j[:n]...)
	}

	v := &CredentialVault{Path: p, body: d, cur: 0}

	return v, err
}

// Read implements io.Reader
func (c *CredentialVault) Read(p []byte) (int, error) {
	if c.cur >= len(c.body) {
		return 0, io.EOF
	}

	x := len(c.body) - c.cur

	n, bound := 0, 0
	if x >= len(p) {
		bound = len(p)
	} else if x <= len(p) {
		bound = x
	}

	for n < bound {
		p[n] = c.body[c.cur]
		n++
		c.cur++
	}

	return n, nil
}

// Writer implements io.Writer
func (c *CredentialVault) Write(p []byte) (int, error) {
	i := len(p)

	c.Credentials = &AWSCredentials{}
	err := json.Unmarshal(p, c.Credentials)
	c.Credentials.Expiration = time.Now().Add(AWSCredentialDuration)

	return i, err
}

func getVaultFilePath(p string) (string, error) {
	var err error
	d := getVaultDir()
	if p == "" {
		p, err = getAWSProfile()
		if err != nil {
			return "", err
		}
	}
	r := path.Join(d, p)

	if _, err := os.Stat(r); os.IsNotExist(err) {
		return r, ErrVaultFileNotExist
	}

	return r, nil
}

func getVaultDir() string {
	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	p := path.Join(u.HomeDir, AWSCredsVaultBaseDir)

	return p
}

func getAWSProfile() (string, error) {
	var p string

	if len(os.Args) == 2 {
		p = os.Args[1]
		return p, nil
	}
	if p = os.Getenv("AWS_PROFILE"); len(p) != 0 {
		return p, nil
	}
	if p = os.Getenv("AWS_DEFAULT_PROFILE"); len(p) != 0 {
		return p, nil
	}

	return "", errAWSProfileNotFound
}
