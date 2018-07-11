package main

import (
	"encoding/pem"
	"io/ioutil"
	"os"
	"github.com/tehmoon/errors"
	"syscall"
	"io"
	"golang.org/x/crypto/scrypt"
	"crypto/rand"
	"crypto/subtle"
	"github.com/spf13/viper"
	"crypto/cipher"
	"crypto/aes"
	"strconv"
	"bytes"
	"strings"
	ivyParse "robpike.io/ivy/parse"
	ivyRun "robpike.io/ivy/run"
	ivyScan "robpike.io/ivy/scan"
	ivyConfig "robpike.io/ivy/config"
	ivyExec "robpike.io/ivy/exec"
	"time"
)

func parseDurationString(duration string, base time.Duration) (time.Duration, error) {
	var dd time.Duration

	d, ok := evalMath(duration)
	if ! ok {
		return dd, errors.New("Error parsing --duration flag")
	}

	dd = base * time.Duration(d)
	if int64(dd) < 0 {
		return dd, errors.New("Duration flag cannot be negative")
	}

	return dd, nil
}

func evalMath(s string) (int64, bool) {
	buf := bytes.NewBuffer(make([]byte, 0))

	conf := &ivyConfig.Config{}
	conf.SetFormat("")
	conf.SetMaxDigits(1e9)
	conf.SetOrigin(1)
	conf.SetPrompt("")
	conf.SetOutput(buf)

	context := ivyExec.NewContext(conf)

	scanner := ivyScan.New(context, "", strings.NewReader(s))
	parser := ivyParse.NewParser("", scanner, context)

	sync := make(chan bool)

	go func(sync chan bool) {
		sync <- ivyRun.Run(parser, context, false)
	}(sync)

	ok := <- sync
	if ! ok {
		return 0, false
	}

	duration := buf.String()

	i, err := strconv.ParseInt(duration[:len(duration) - 1], 10, 64)
	if err != nil {
		return 0, false
	}

	return i, true
}

func InitPasswordFile(file, password string) ([]byte, error) {
	salt := make([]byte, 16)

	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading random stream")
	}

	dk, err := DerivePassword(password, salt)
	if err != nil {
		return nil, errors.Wrap(err, "Error deriving key from password")
	}

	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating the password file")
	}
	defer f.Close()

	key := make([]byte, len(salt) + len(dk))
	copy(key, salt)
	copy(key[len(salt):], dk)

	_, err = f.Write(key)
	if err != nil {
		return nil, errors.Wrap(err, "Error writing salt and derived key to password file")
	}

	return dk, nil
}

func ReadPasswordFile(file string) ([]byte, []byte, error) {
	key, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error opening the password file")
	}

	if len(key) != 16 + 32 {
		return nil, nil, ErrCorruptedPasswordFile
	}

	salt := key[:16]
	dk := key[16:]

	return salt, dk, nil
}

func DerivePassword(password string, salt []byte) ([]byte, error) {
	dk, err := scrypt.Key([]byte(password), salt, 1 << 20, 8, 1, 32)
	if err != nil {
		return nil, errors.Wrap(err, "Error executing scrypt")
	}

	return dk, nil
}

func VerifyPassword(password string, salt, dk []byte) (error) {
	dkk, err := scrypt.Key([]byte(password), salt, 1 << 20, 8, 1, 32)
	if err != nil {
		return errors.Wrap(err, "Error executing scrypt")
	}

	ok := subtle.ConstantTimeCompare(dkk, dk)
	if ok == 0 {
		return ErrBadPassword
	}

	return nil
}

func LoadPEM(p string, dk []byte) (*pem.Block, error) {
	data, err := readData(p, dk)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(data)
	if len(rest) > 0 {
		return nil, errors.New("Error decoding PEM data")
	}

	return block, nil
}

func createAESGCMBlock(dk []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating AES cipher block")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating AES-GCM stream")
	}

	return aesgcm, nil
}

func readData(p string, dk []byte) ([]byte, error) {
	payload, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, errors.Wrap(err, "Error opening file")
	}

	aead, err := createAESGCMBlock(dk)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)

	read := copy(nonce, payload)
	if read != len(nonce) {
		return nil, errors.Wrap(ErrCorruptedFile, "Nonce from file couldn't be fully read")
	}

	data, err := aead.Open(nil, nonce, payload[len(nonce):], nil)
	if err != nil {
		return nil, errors.Wrap(ErrCorruptedFile, "Error in decrypting the file")
	}

	return data, nil
}

func writeData(p string, data, dk []byte) (error) {
	nonce := make([]byte, 12)

	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return errors.Wrap(err, "Error creating nonce")
	}

	aead, err := createAESGCMBlock(dk)
	if err != nil {
		return err
	}

	payload := make([]byte, len(nonce) + len(data) + 16 /* gcm tag */)
	copy(payload, nonce)

	enc := aead.Seal(nil, nonce, data, nil)
	copy(payload[len(nonce):], enc)

	err = ioutil.WriteFile(p, payload, 0600)
	if err != nil {
		return errors.Wrap(err, "Error writing data to file")
	}

	return nil
}

func EnsureAbsentFile(p string) (error) {
	_, err := os.Lstat(p)
	if err != nil {
		if e, ok := err.(*os.PathError); ok {
			if e.Err == syscall.ENOENT {
				return nil
			}
		}

		return err
	}

	return ErrFileAlreadyExists
}

func EnsureCertificateKey(base, name string) (error) {
	err := EnsureCertificate(base, name)
	if err != nil {
		return err
	}

	err = EnsurePrivateKey(base, name)
	if err != nil {
		return err
	}

	return nil
}

func EnsureFiles(files ...string) (error) {
	for _, file := range files {
		err := EnsureFile(file)
		if err != nil {
			return errors.Wrapf(err, "Error ensuring file: %s\n", file)
		}
	}

	return nil
}

func EnsureFile(file string) (error) {
	err := EnsureAbsentFile(file)
	if err != nil {
		if err == ErrFileAlreadyExists {
			return nil
		}

		return err
	}

	return ErrFileNotFound
}

func EnsureAbsentCertificateKey(base, name string) (error) {
	err := EnsureAbsentCertificate(base, name)
	if err != nil {
		return err
	}

	err = EnsureAbsentPrivateKey(base, name)
	if err != nil {
		return err
	}

	return nil
}

func EnsureAbsentFiles(files ...string) (error) {
	for _, file := range files {
		err := EnsureAbsentFile(file)
		if err != nil {
			return errors.Wrapf(err, "Error ensuring absent file: %s\n", file)
		}
	}

	return nil
}

func createDirectory(p string) (error) {
	d, err := os.Open(p)
	if err != nil {
		if e, ok := err.(*os.PathError); ok {
			if e.Err == syscall.ENOENT {
				return os.Mkdir(p, 0700)
			}
		}

		return err
	}
	defer d.Close()

	err = CheckInitDirectory(p)
	if err == nil {
		return errors.WrapErr(err, ErrCommandDirectoryAlreadyExists)
	}

	ff, err := d.Readdir(1)
	if err != nil {
		if err == io.EOF {
			return nil
		}

		return errors.Wrap(err, "Error listing files in directory")
	}

	if len(ff) > 0 {
		return ErrCommandDirectoryNotEmpty
	}

	return nil
}

func GetByteSlice(config *viper.Viper, key string) ([]byte) {
	v := config.Get(key)

	if v == nil {
		return nil
	}

	if value, ok := v.([]byte); ok {
		return value
	}

	return nil
}

func GetConfigDK(config *viper.Viper) ([]byte) {
	return GetByteSlice(config, "key")
}
