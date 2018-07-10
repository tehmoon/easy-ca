package main

import (
	"math/big"
	"io"
	"crypto"
	"crypto/x509/pkix"
	"time"
	"github.com/tehmoon/errors"
	"crypto/x509"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	flag "github.com/spf13/pflag"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/abiosoft/ishell"
)

type CommandCreateCA struct {
	flags *viper.Viper
	config *viper.Viper
	name string
	template *x509.Certificate
	duration time.Duration
}

func (cmd CommandCreateCA) Config() (*viper.Viper) {
	return cmd.config
}

func (cmd CommandCreateCA) Flags() (*viper.Viper) {
	return cmd.flags
}

func (cmd *CommandCreateCA) Init(set *flag.FlagSet, args []string) (error) {
	cmd.name = cmd.flags.GetString("name")
	if cmd.name == "" {
		return errors.Wrap(ErrCommandBadFlags, "Name flag cannot be empty")
	}

	var err error

	cmd.duration, err = parseDurationString(cmd.flags.GetString("duration"), time.Second)
	if err != nil {
		return errors.WrapErr(ErrCommandBadFlags, err)
	}

	return nil
}

func (cmd CommandCreateCA) Do() (error) {
	path := cmd.flags.GetString("path")

	err := EnsureAbsentCertificateKey(path, "ca")
	if err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Wrap(err, "Failed to create the private key")
	}

	template, err := createCATemplate(cmd.name, cmd.duration)
	if err != nil {
		return errors.Wrap(err, "Error generating the certificate's template")
	}

	cert, err := signCertificate(template, template, key, key.Public())
	if err != nil {
		return err
	}

	dk := GetConfigDK(cmd.config)

	err = SaveCertificate(path, "ca", cert, dk)
	if err != nil {
		return errors.Wrap(err, "Error saving ca.crt file")
	}

	err = SavePrivateKey(path, "ca", key, dk)
	if err != nil {
		return errors.Wrap(err, "Error saving ca.key file")
	}

	return nil
}

func createCATemplate(name string, valid time.Duration) (*x509.Certificate, error) {
	now := time.Now()

	if uint64(valid) < 0 {
		return nil, errors.Wrap(ErrCommandNegativeDuration, "Bad valid time period")
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: name,
		},
		IsCA: true,
		NotBefore: now,
		NotAfter: now.Add(valid),
		MaxPathLen: 0,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
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

func NewCommandCreateCA(config, flags *viper.Viper, ctx *ishell.Context) (*cobra.Command) {
	cmd := &cobra.Command{
		Use: "create-ca",
		Args: cobra.ExactArgs(0),
		RunE: ExecuteCommand(&CommandCreateCA{
			flags: flags,
			config: config,
		}, ctx),
	}

	cmd.Flags().StringP("name", "n", "", "Common Name for the CA")
	cmd.Flags().StringP("duration", "d", "3600 * 24 * 365", "Set the Not Valid After field in second. Support arithmetic operations")

	cmd.MarkFlagRequired("name")

	flags.BindPFlags(cmd.Flags())

	return cmd
}

func LoadCA(base string, dk []byte) (*x509.Certificate, crypto.PrivateKey, error) {
	crt, err := LoadCertificate(base, "ca", dk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error loading CA certificate")
	}

	key, err := LoadPrivateKey(base, "ca", dk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error loading CA key")
	}

	return crt, key, nil
}
