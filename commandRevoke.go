package main

import (
	"github.com/tehmoon/errors"
	"crypto/x509/pkix"
	"time"
	"crypto/x509"
	flag "github.com/spf13/pflag"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/abiosoft/ishell"
)

type CommandRevoke struct {
	name string
	template *x509.Certificate
	flags *viper.Viper
	config *viper.Viper
	context *ishell.Context
}

func (cmd CommandRevoke) Config() (*viper.Viper) {
	return cmd.config
}

func (cmd CommandRevoke) Flags() (*viper.Viper) {
	return cmd.flags
}

func (cmd *CommandRevoke) Init(set *flag.FlagSet, args []string) (error) {
	cmd.name = cmd.flags.GetString("name")
	if cmd.name == "" {
		return errors.Wrap(ErrCommandBadFlags, "Name flag cannot be empty")
	}

	return nil
}

func Revoke(base, name string, dk []byte) (error) {
	if name == "ca" {
		return errors.New("Revoking CA is not yet implemented")
	}

	err := EnsureCertificateKey(base, name)
	if err != nil {
		return err
	}

	cert, err := LoadCertificate(base, name, dk)
	if err != nil {
		return errors.Wrapf(err, "Error loading the certificate %q", name)
	}

	revoked := &pkix.RevokedCertificate{
		SerialNumber: cert.SerialNumber,
		RevocationTime: time.Now(),
	}

	err = SaveExpiredCertificate(base, name, revoked, dk)
	if err != nil {
		return errors.Wrapf(err, "Error saving revoked certificate %q", name)
	}

	DeleteCertificate(base, name)
	DeletePrivateKey(base, name)

	return nil
}

func (cmd CommandRevoke) Do() (error) {
	dk := GetConfigDK(cmd.config)

	err := Revoke(cmd.flags.GetString("path"), cmd.name, dk)
	if err != nil {
		return errors.Wrap(err, "Error revoking certificate")
	}

	err = UpdateCRL(cmd.config, cmd.context)
	if err != nil {
		return err
	}

	return nil
}

func NewCommandRevoke(config, flags *viper.Viper, ctx *ishell.Context) (*cobra.Command) {
	cmd := &cobra.Command{
		Use: "revoke",
		Args: cobra.ExactArgs(0),
		RunE: ExecuteCommand(&CommandRevoke{
			flags: flags,
			config: config,
			context: ctx,
		}, ctx),
	}

	cmd.Flags().StringP("name", "n", "", "Common Name to revoke")

	cmd.MarkFlagRequired("name")

	flags.BindPFlags(cmd.Flags())

	return cmd
}
