package main

import (
	"bytes"
	"errors"
	// "fmt"
	"io"
	// "log"
	// "os"
	"os/exec"
	// "strings"
)

var (
	errMissingGPG = errors.New("unable to find gpg exe in your path")
)

// GPGCommander sends commands to GPG and manages arguments.
type GPGCommander struct {
	exec    *exec.Cmd
	gpgPath *bytes.Buffer
	KeyID   []byte
}

type GPGCommandConfig struct {
	Stdin io.Reader
	Args  []string
}

// Path returns the path to the GPG exe
func (g *GPGCommander) Path() string {
	err := locateGPG(g.gpgPath)
	if err != nil {
		return ""
	}

	return g.gpgPath.String()
}

// Create a new GPG commander.
func NewGPGCommander() (*GPGCommander, error) {
	cr := &GPGCommander{gpgPath: &bytes.Buffer{}}
	cmdPath := cr.Path()
	if len(cmdPath) <= 0 {
		return cr, errMissingGPG
	}
	cr.exec = exec.Command(cmdPath)

	return cr, nil
}

// Run a command against a GPG binary.
func (g *GPGCommander) Run(f io.Writer, args ...string) error {
	g.exec.Stdout = f
	g.exec.Stdout = f
	g.exec.Args = args

	if err := g.exec.Run(); err != nil {
		return err
	}

	return nil
}

// Decrypt a file and pass the result to the writer.
func (g *GPGCommander) Decrypt(f io.Writer, config *GPGCommandConfig) error {
	g.exec.Stdin = config.Stdin
	g.exec.Stdout = f
	g.exec.Args = append([]string{"--decrypt"}, config.Args...)

	err := g.exec.Start()
	if err != nil {
		return err
	}

	if err = g.exec.Wait(); err != nil {
		return err
	}

	return nil
}

func locateGPG(i io.Writer) error {
	cmd, err := exec.LookPath("gpg")
	if err != nil {
		err = errMissingGPG
	}
	i.Write([]byte(cmd))

	return err
}
