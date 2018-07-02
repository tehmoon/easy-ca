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
	update bool
	export bool
	ctx *ishell.Context
}

func (cmd CommandCRL) Config() (*viper.Viper) {
	return cmd.config
}

func (cmd CommandCRL) Flags() (*viper.Viper) {
	return cmd.flags
}

func (cmd *CommandCRL) Init(set *flag.FlagSet, args []string) (error) {
	cmd.update = cmd.flags.GetBool("update")
	cmd.export = cmd.flags.GetBool("export")
	if (! cmd.update && ! cmd.export) || (cmd.update && cmd.export) {
		return errors.Wrap(ErrCommandBadFlags, "Use one of --update or --export")
	}

	return nil
}

func (cmd CommandCRL) Do() (error) {
	dk := GetConfigDK(cmd.config)

	path := cmd.flags.GetString("path")

	if cmd.update {
		err := CreateCRL(path, dk)
		if err != nil {
			return errors.Wrap(err, "Error creating CRL")
		}
	} else if cmd.export {
		err := ExportCRL(path, "pem", cmd.ctx, dk)
		if err != nil {
			return errors.Wrap(err, "Error exporting CRL")
		}
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
			ctx: ctx,
		}, ctx),
	}

	cmd.Flags().Bool("update", false, "Update Certificate Revocation List")
	cmd.Flags().Bool("export", false, "Export Certificate Revocation List")

	flags.BindPFlags(cmd.Flags())

	return cmd
}
