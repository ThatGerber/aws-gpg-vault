package main

import (
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"gopkg.in/ini.v1"
	"io"
	"log"
	"os"
	"os/user"
	"path"
	"time"
)

var (
	// AWSCredentialSourceVersion is the version of the credential_source output
	AWSCredentialSourceVersion = 1
	// DefaultAWSAssumeRoleSessionName is the name of the session created by
	// assuming roles.
	DefaultAWSAssumeRoleSessionName = "aws-gpg-vault-session"
	// DefaultAWSConfigFilePath is the default location of AWS CLI config.
	DefaultAWSConfigFilePath = ".aws/config"
	// DefaultAWSConfigFileEnv is the env containing the config file path.
	DefaultAWSConfigFileEnv = "AWS_CONFIG_FILE"
	// AssumeRoleTokenProvider is a custom provider for MFA assume role requests
	AssumeRoleTokenProvider func() (string, error)
	// AWSCredsVaultBaseDir is the path from the home dir to the encrypted files
	AWSCredsVaultBaseDir = ".aws/creds-vault"
	// AWSCredentialDuration refers to the default amount of time credentials
	// should be valid.
	AWSCredentialDuration = time.Duration(8) * time.Hour
	// ErrVaultFileNotExist is returned when the application is unable to locate
	// a suitable file.
	ErrVaultFileNotExist     = errors.New("unable to find aws-gpg-vault file")
	errAWSProfileNotFound    = errors.New("unable to determine AWS config profile")
	errAWSConfigFileNotFound = errors.New("unable to determine AWS config file")
	errAWSRoleArnNotFound    = errors.New("unable to determine requested AWS Role ARN")
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
	Path           string
	body           []byte
	cur            int
	Credentials    *AWSCredentials
	SrcCredentials *credentials.Credentials
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
	if err != nil {
		return i, err
	}

	prf, err := getAWSProfile()
	if err != nil {
		return i, err
	}
	cfg, oerr := getAWSConfig(prf)
	if oerr != nil && oerr == errAWSConfigFileNotFound {
		return i, err
	}

	srccr := *c.Credentials
	cfg.Source = &srccr

	cr, err := c.getAssumeRoleCredentials(cfg)
	if err != nil {
		return i, err
	}

	assumedCreds, err := cr.Get()
	if err != nil {
		return i, err
	}
	c.Credentials = &AWSCredentials{
		Version:         AWSCredentialSourceVersion,
		AccessKeyID:     assumedCreds.AccessKeyID,
		SecretAccessKey: assumedCreds.SecretAccessKey,
		SessionToken:    assumedCreds.SessionToken,
		Expiration:      time.Now().Add(stscreds.DefaultDuration),
	}

	return i, nil
}

func (c *CredentialVault) getAssumeRoleCredentials(config *ProfileConfig) (*credentials.Credentials, error) {
	c.SrcCredentials = credentials.NewStaticCredentials(
		config.Source.AccessKeyID,
		config.Source.SecretAccessKey,
		config.Source.SessionToken,
	)

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            *aws.NewConfig().WithCredentials(c.SrcCredentials),
	}))

	if len(config.MFASerial) > 0 && AssumeRoleTokenProvider == nil {
		// AssumeRole Token provider is required if doing Assume Role
		// with MFA.
		return nil, session.AssumeRoleTokenProviderNotSetError{}
	}
	assumeCreds := stscreds.NewCredentials(
		sess,
		config.RoleArn,
		func(opt *stscreds.AssumeRoleProvider) {
			opt.RoleSessionName = config.SessionName

			if len(config.ExternalID) > 0 {
				opt.ExternalID = aws.String(config.ExternalID)
			}

			// Assume role with MFA
			if len(config.MFASerial) > 0 {
				opt.SerialNumber = aws.String(config.MFASerial)
				opt.TokenProvider = AssumeRoleTokenProvider
			}
		},
	)

	return assumeCreds, nil
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

// ProfileConfig for assuming a role
type ProfileConfig struct {
	SessionName string
	RoleArn     string
	ExternalID  string
	MFASerial   string
	Source      *AWSCredentials
}

func getAWSConfig(profile string) (*ProfileConfig, error) {
	cfgFile := os.Getenv(DefaultAWSConfigFileEnv)
	if cfgFile == "" {
		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		cfgFile = path.Join(u.HomeDir, DefaultAWSConfigFilePath)
	}

	cfg, err := ini.Load(cfgFile)
	if err != nil {
		err = errAWSConfigFileNotFound
		return nil, err
	}
	pCfg := cfg.Section(profile)
	r := &ProfileConfig{
		SessionName: pCfg.Key("role_session_name").Validate(func(in string) string {
			if len(in) == 0 {
				return DefaultAWSAssumeRoleSessionName
			}
			return in
		}),
		RoleArn:    pCfg.Key("role_arn").String(),
		ExternalID: pCfg.Key("external_id").String(),
		MFASerial:  pCfg.Key("mfa_serial").String(),
	}

	return r, nil
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
