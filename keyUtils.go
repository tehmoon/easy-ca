package main

import (
	"io/ioutil"
	"path/filepath"
	"crypto/x509"
	"github.com/tehmoon/errors"
	"crypto"
	"crypto/ecdsa"
	"encoding/pem"
	"os"
	"fmt"
	"github.com/abiosoft/ishell"
	homedir "github.com/mitchellh/go-homedir"
)

func LoadPrivateKey(base, name string, dk []byte) (crypto.PrivateKey, error) {
	block, err := LoadPEM(filepath.Join(base, "keys", name + ".key"), dk)
	if err != nil {
		return nil, err
	}

	if block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("Not a private key")
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing private key")
	}

	return priv, nil
}

func SavePrivateKey(base, name string, priv crypto.PrivateKey, dk []byte) (error) {
	data, err := EncodePrivateKey(priv)
	if err != nil {
		return errors.Wrap(err, "Error encoding private key")
	}

	file := filepath.Join(base, "keys", name + ".key")

	return writeData(file, data, dk)
}

func EncodePrivateKey(priv crypto.PrivateKey) ([]byte, error) {
	var (
		data []byte
		err error
		t string
	)

	switch p := priv.(type) {
		case *ecdsa.PrivateKey:
			data, err = x509.MarshalECPrivateKey(p)
			if err != nil {
				return nil, err
			}

			t = "EC PRIVATE KEY"

		default:
			return nil, errors.Wrapf(ErrCommandUnsupportedPrivateKey, "Unsupported private key of type %T", p)
	}

	b := &pem.Block{
		Type: t,
		Bytes: data,
	}

	return pem.EncodeToMemory(b), nil
}

func EnsurePrivateKey(base, name string) (error) {
	err := EnsureFile(filepath.Join(base, "keys", name + ".key"))
	if err != nil {
		return errors.Wrapf(err, "Error ensuring Key for %q", name)
	}

	return nil
}

func EnsureAbsentPrivateKey(base, name string) (error) {
	err := EnsureAbsentFile(filepath.Join(base, "keys", name + ".key"))
	if err != nil {
		return errors.Wrapf(err, "Error ensuring absent Key for %q", name)
	}

	return nil
}

func ExportPrivateKey(base, name, format, outputDir string, ctx *ishell.Context, dk []byte) (error) {
	key, err := LoadPrivateKey(base, name, dk)
	if err != nil {
		return errors.Wrap(err, "Error loading certificate")
	}

	var output string

	switch format {
		case "pem":
			data, err := EncodePrivateKey(key)
			if err != nil {
				return errors.Wrap(err, "Error encoding private key to pem")
			}

			output = string(data[:])
		default:
			return errors.Errorf("Bad format of %q", format)
	}

	if outputDir != "" {
		dir, err := homedir.Expand(outputDir)
		if err != nil {
			return errors.Wrap(err, "Error expanding directory")
		}

		path := filepath.Join(dir, name + ".key")

		err = ioutil.WriteFile(path, []byte(output), 0600)
		if err != nil {
			return errors.Wrap(err, "Error writing file")
		}

		return nil
	}

	if ctx != nil {
		ctx.Printf("%s", output)

		return nil
	}

	fmt.Printf("%s", output)

	return nil
}

func DeletePrivateKey(base, name string) (error) {
	return os.Remove(filepath.Join(base, "keys", name + ".key"))
}
