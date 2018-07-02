package main

import (
	"os"
	"path"
	"path/filepath"
	"io"
	"crypto/x509/pkix"
	"encoding/asn1"
	"crypto/rand"
	"math/big"
	"encoding/pem"
	"fmt"
	"crypto"
	"time"
	"github.com/tehmoon/errors"
	"github.com/abiosoft/ishell"
	"crypto/x509"
	"io/ioutil"
	homedir "github.com/mitchellh/go-homedir"
)

func createTemplate(name string, valid time.Duration) (*x509.Certificate, error) {
	now := time.Now()

	if uint64(valid) < 0 {
		return nil, errors.Wrap(ErrCommandNegativeDuration, "Bad valid time period")
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: now,
		NotAfter: now.Add(valid),
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	template.SubjectKeyId = make([]byte, 20)

	_, err := io.ReadFull(rand.Reader, template.SubjectKeyId)
	if err != nil {
		return nil, errors.Wrap(err, "Error generating subject key id")
	}

	sn := make([]byte, 20)

	_, err = io.ReadFull(rand.Reader, sn)
	if err != nil {
		return nil, errors.Wrap(err, "Error generating serial number")
	}

	template.SerialNumber = new(big.Int).SetBytes(sn)

	return template, nil
}

func LoadCertificate(base, name string, dk []byte) (*x509.Certificate, error) {
	block, err := LoadPEM(filepath.Join(base, "certificates", name + ".crt"), dk)
	if err != nil {
		return nil, err
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("Not a certificate")
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing certificate")
	}

	return crt, nil
}

func LoadExpiredCertificate(base, name string, dk []byte) (*pkix.RevokedCertificate, error) {
	block, err := LoadPEM(filepath.Join(base, "revoked", name + ".crt"), dk)
	if err != nil {
		return nil, err
	}

	if block.Type != "REVOKED CERTIFICATE" {
		return nil, errors.New("Not a revoked certificate")
	}

	crt := &pkix.RevokedCertificate{}

	rest, err := asn1.Unmarshal(block.Bytes, crt)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing expired certificate")
	}

	if len(rest) > 0 {
		return nil, errors.New("Error loading the expired certificate")
	}

	return crt, nil
}

func SaveCertificate(base, name string, cert *x509.Certificate, dk []byte) (error) {
	file := filepath.Join(base, "certificates", name + ".crt")

	return writeData(file, EncodeCertificate(cert), dk)
}

func SaveExpiredCertificate(base, name string, cert *pkix.RevokedCertificate, dk []byte) (error) {
	payload, err := EncodeExpiredCertificate(cert)
	if err != nil {
		return errors.Wrap(err, "Error encoding")
	}

	file := filepath.Join(base, "revoked", name + ".crt")

	return writeData(file, payload, dk)
}

func EncodeExpiredCertificate(cert *pkix.RevokedCertificate) ([]byte, error) {
	payload, err := asn1.Marshal(*cert)
	if err != nil {
		return nil, errors.Wrap(err, "Error marshaling to asn1")
	}

	b := &pem.Block{
		Type: "REVOKED CERTIFICATE",
		Bytes: payload,
	}

	return pem.EncodeToMemory(b), nil
}

func EncodeCertificate(cert *x509.Certificate) ([]byte) {
	b := &pem.Block{
		Type: "CERTIFICATE",
		Bytes: cert.Raw,
	}

	return pem.EncodeToMemory(b)
}

func EncodeCRL(crl []byte) ([]byte) {
	b := &pem.Block{
		Type: "X509 CRL",
		Bytes: crl,
	}

	return pem.EncodeToMemory(b)
}

func EnsureCertificate(base, name string) (error) {
	err := EnsureFile(filepath.Join(base, "certificates", name + ".crt"))
	if err != nil {
		return errors.Wrapf(err, "Error ensuring Certicate for %q", name)
	}

	return nil
}

func signCertificate(template, req *x509.Certificate, priv crypto.PrivateKey, pub crypto.PublicKey) (*x509.Certificate, error) {
	raw, err := x509.CreateCertificate(rand.Reader, template, req, pub, priv)
	if err != nil {
		return nil, errors.Wrap(err, "Error signing the certificate's template")
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing the newly created certificate")
	}

	return cert, nil
}
func EnsureAbsentCertificate(base, name string) (error) {
	err := EnsureAbsentFile(filepath.Join(base, "certificates", name + ".crt"))
	if err != nil {
		return errors.Wrapf(err, "Error ensuring absent Certicate for %q", name)
	}

	return nil
}

func ExportCertificate(base, name, format, outputDir string, ctx *ishell.Context, dk []byte) (error) {
	crt, err := LoadCertificate(base, name, dk)
	if err != nil {
		return errors.Wrap(err, "Error loading certificate")
	}

	var output string

	switch format {
		case "pem":
			data := EncodeCertificate(crt)
			output = string(data[:])
		default:
			return errors.Errorf("Bad format of %q", format)
	}

	if outputDir != "" {
		dir, err := homedir.Expand(outputDir)
		if err != nil {
			return errors.Wrap(err, "Error expanding directory")
		}

		path := filepath.Join(dir, name + ".crt")

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

func ListExpiredCertificates(base string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(base, "revoked", "*.crt"))
	if err != nil {
		return nil, errors.Wrap(err, "Error listing expired certificates")
	}

	return files, nil
}

func LoadExpiredCertificates(base string, dk []byte) ([]pkix.RevokedCertificate, error) {
	names, err := ListExpiredCertificates(base)
	if err != nil {
		return nil, errors.Wrap(err, "Error listing expired certificates")
	}

	certs := make([]pkix.RevokedCertificate, 0)

	for _, name := range names {
		name = filepath.Base(name)
		ext := path.Ext(name)

		cert, err := LoadExpiredCertificate(base, name[:len(name) - len(ext)], dk)
		if err != nil {
			return nil, errors.Wrapf(err, "Error loading revoked certificate %q", name)
		}

		certs = append(certs, *cert)
	}

	return certs, nil
}

func ExportCRL(base, format, outputDir string, ctx *ishell.Context, dk []byte) (error) {
	var crl string

	switch format {
		case "pem":
			data, err := readData(filepath.Join(base, "crl.crt"), dk)
			if err != nil {
				return errors.Wrap(err, "Error reading CRL")
			}

			crl = string(data[:])

		default:
			return errors.Errorf("Format %q not yet implemented", format)
	}

	if outputDir != "" {
		dir, err := homedir.Expand(outputDir)
		if err != nil {
			return errors.Wrap(err, "Error expanding directory")
		}

		path := filepath.Join(dir, "crl.crt")

		err = ioutil.WriteFile(path, []byte(crl), 0600)
		if err != nil {
			return errors.Wrap(err, "Error writing file")
		}

		return nil
	}

	if ctx == nil {
		fmt.Printf("%s", crl)

		return nil
	}

	ctx.Printf("%s", crl)

	return nil
}

func CreateCRL(base string, dk []byte) (error) {
	crt, key, err := LoadCA(base, dk)
	if err != nil {
		return errors.Wrap(err, "Error loading ca")
	}

	certs, err := LoadExpiredCertificates(base, dk)
	if err != nil {
		return errors.Wrap(err, "Error loading revoked certificates")
	}

	now := time.Now()

	crl, err := crt.CreateCRL(rand.Reader, key, certs, now, now.Add(time.Hour))
	if err != nil {
		return errors.Wrap(err, "Error creating CRL")
	}

	err = writeData(filepath.Join(base, "crl.crt"), EncodeCRL(crl), dk)
	if err != nil {
		return errors.Wrap(err, "error writing the CRL")
	}

	return nil
}

func DeleteCertificate(base, name string) (error) {
	return os.Remove(filepath.Join(base, "certificates", name + ".crt"))
}
