package main

import (
	"encoding/json"
	"log"
)

type AWSCredentials struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
}

func (a *AWSCredentials) String() string {
	r, err := json.Marshal(a)
	if err != nil {
		log.Fatal(err)
	}

	return string(r)
}
