package main

import (
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

type CommandCreate struct {
	flags *viper.Viper
	config *viper.Viper
	name string
	template *x509.Certificate
	server bool
	client bool
	altDNS []string
	duration time.Duration
}

func (cmd *CommandCreate) Init(set *flag.FlagSet, args []string) (error) {
	cmd.name = cmd.flags.GetString("name")
	if cmd.name == "" {
		return errors.Wrap(ErrCommandBadFlags, "Name flag cannot be empty")
	}

	cmd.server = cmd.flags.GetBool("server")
	cmd.client = cmd.flags.GetBool("client")
	if (! cmd.server && ! cmd.client) || (cmd.server && cmd.client) {
		return errors.Wrap(ErrCommandBadFlags, "Use one of --server or --client")
	}

	var err error

	cmd.duration, err = parseDurationString(cmd.flags.GetString("duration"), time.Second)
	if err != nil {
		return errors.WrapErr(ErrCommandBadFlags, err)
	}

	return nil
}

func (cmd CommandCreate) Config() (*viper.Viper) {
	return cmd.config
}

func (cmd CommandCreate) Flags() (*viper.Viper) {
	return cmd.flags
}

func (cmd CommandCreate) Do() (error) {
	path := cmd.flags.GetString("path")
	dk := GetConfigDK(cmd.config)

	err := EnsureAbsentCertificateKey(path, cmd.name)
	if err != nil {
		return err
	}

	caCert, caKey, err := LoadCA(path, GetConfigDK(cmd.config))
	if err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Wrap(err, "Failed to create the private key")
	}

	var template *x509.Certificate

	if cmd.server {
		template, err = createTemplateServer(cmd.name, cmd.duration)
		if err != nil {
			return errors.Wrap(err, "Error generating the certificate's template for server")
		}
	} else if cmd.client {
		template, err = createTemplateClient(cmd.name, cmd.duration)
		if err != nil {
			return errors.Wrap(err, "Error generating the certificate's template for client")
		}
	} else {
		return errors.New("Unknown certificate's client/server usage")
	}

	for _, name := range cmd.altDNS {
		template.DNSNames = append(template.DNSNames, name)
	}

	cert, err := signCertificate(template, caCert, caKey, key.Public())
	if err != nil {
		return err
	}

	err = SaveCertificate(path, cmd.name, cert, dk)
	if err != nil {
		return errors.Wrap(err, "Error saving certificate")
	}

	err = SavePrivateKey(path, cmd.name, key, dk)
	if err != nil {
		return errors.Wrap(err, "Error saving key")
	}

	return nil
}

func NewCommandCreate(config, flags *viper.Viper, ctx *ishell.Context) (*cobra.Command) {
	cc := &CommandCreate{
		flags: flags,
		config: config,
	}
	cmd := &cobra.Command{
		Use: "create",
		Args: cobra.ExactArgs(0),
		RunE: ExecuteCommand(cc, ctx),
	}

	cmd.Flags().StringP("name", "n", "", "Common Name for the certificate")
	cmd.Flags().Bool("server", false, "Use certificate server's side")
	cmd.Flags().Bool("client", false, "Use certificate client's side")
	cmd.Flags().StringP("duration", "d", "3600 * 24 * 30 * 3", "Set the Not Valid After field in second. Support arithmetic operations")
	cmd.Flags().StringArrayVar(&cc.altDNS, "alt-dns", make([]string, 0), "Set alternative names")

	cmd.MarkFlagRequired("name")

	flags.BindPFlags(cmd.Flags())

	return cmd
}

func createTemplateClient(name string, valid time.Duration) (*x509.Certificate, error) {
	template, err := createTemplate(name, valid)
	if err != nil {
		return nil, err
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,}

	return template, nil
}

func createTemplateServer(name string, valid time.Duration) (*x509.Certificate, error) {
	template, err := createTemplate(name, valid)
	if err != nil {
		return nil, err
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,}
	template.DNSNames = append(template.DNSNames, name)

	return template, nil
}
