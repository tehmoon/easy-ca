package main

import (
	"github.com/tehmoon/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/abiosoft/ishell"
	"crypto/x509"
)

type CommandCRL struct {
	flags *viper.Viper
	template *x509.Certificate
	config *viper.Viper
}

func (cmd CommandCRL) Config() (*viper.Viper) {
	return cmd.config
}

func (cmd CommandCRL) Flags() (*viper.Viper) {
	return cmd.flags
}

func (cmd *CommandCRL) Init(set *flag.FlagSet, args []string) (error) {
	return nil
}

func (cmd CommandCRL) Do() (error) {
	dk := GetConfigDK(cmd.config)

	err := CreateCRL(cmd.flags.GetString("path"), dk)
	if err != nil {
		return errors.Wrapf(err, "Error creating CRL")
	}

	return nil
}

func NewCommandCRL(config, flags *viper.Viper, ctx *ishell.Context) (*cobra.Command) {
	cmd := &cobra.Command{
		Use: "crl",
		Args: cobra.ExactArgs(0),
		RunE: ExecuteCommand(&CommandCRL{
			flags: flags,
			config: config,
		}, ctx),
	}

	return cmd
}
