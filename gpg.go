package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

var (
	errMissingGPG = errors.New("unable to find gpg exe in your path")
)

// GPGCommandConfig contains command config for GPG.
type GPGCommandConfig struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Args           []string
	KeyID          string
}

// GPGCommander sends commands to GPG and manages arguments.
type GPGCommander struct {
	exec    *exec.Cmd
	gpgPath *bytes.Buffer
}

// NewGPGCommander creates a new GPG command executor.
func NewGPGCommander(config *GPGCommandConfig) (*GPGCommander, error) {
	cr := &GPGCommander{gpgPath: &bytes.Buffer{}}
	cmdPath := cr.Path()
	if len(cmdPath) <= 0 {
		return cr, errMissingGPG
	}
	cr.exec = exec.Command(cmdPath)
	cr.Configure(config)

	return cr, nil
}

// ToMap converts the commander to a map for logging and inspecting.
func (g *GPGCommander) ToMap() map[string]string {
	var m map[string]string

	m = map[string]string{
		"gpgPath":     g.gpgPath.String(),
		"exec.path":   g.exec.Path,
		"exec.args":   fmt.Sprintf("%s", g.exec.Args),
		"exec.stdin":  fmt.Sprintf("%s", g.exec.Stdin),
		"exec.stdout": fmt.Sprintf("%s", g.exec.Stdout),
		"exec.stderr": fmt.Sprintf("%s", g.exec.Stderr),
	}

	return m
}

// Path returns the path to the GPG exe
func (g *GPGCommander) Path() string {
	err := locateGPG(g.gpgPath)
	if err != nil {
		return ""
	}

	return g.gpgPath.String()
}

// Configure the GPGCommander using the supplied command config.
func (g *GPGCommander) Configure(config *GPGCommandConfig) error {
	if config != nil {
		if config.Stdin != nil {
			g.exec.Stdin = config.Stdin
		}
		if config.Stdout != nil {
			g.exec.Stdout = config.Stdout
		}
		if config.Stderr != nil {
			g.exec.Stderr = config.Stderr
		}
		if len(config.Args) > 0 {
			g.exec.Args = append(g.exec.Args, config.Args...)
		}
	}

	return nil
}

// Run a command against a GPG binary.
func (g *GPGCommander) Run(f io.Writer, config *GPGCommandConfig, args ...string) error {
	g.Configure(config)

	if f != nil {
		g.exec.Stdout = f
		g.exec.Stderr = f
	}

	err := g.exec.Start()
	if err != nil {
		return err
	}

	if err = g.exec.Wait(); err != nil {
		return err
	}

	return nil
}

// Decrypt a file and pass the result to the writer.
func (g *GPGCommander) Decrypt(f io.Writer, config *GPGCommandConfig) error {
	config.Args = append([]string{"--decrypt"}, config.Args...)
	err := g.Run(f, config)

	return err
}

func locateGPG(i io.Writer) error {
	cmd, err := exec.LookPath("gpg")
	if err != nil {
		err = errMissingGPG
	}
	i.Write([]byte(cmd))

	return err
}
