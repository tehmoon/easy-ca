package main

import (
	"time"
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
	context *ishell.Context
	outputDir string
	duration time.Duration
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

	cmd.outputDir = cmd.flags.GetString("output-dir")

	var err error

	cmd.duration, err = parseDurationString(cmd.flags.GetString("duration"), time.Second)
	if err != nil {
		return errors.WrapErr(ErrCommandBadFlags, err)
	}

	return nil
}

func UpdateCRL(config *viper.Viper, context *ishell.Context) (error) {
	flags := viper.New()
	crl := NewCommandCRL(config, flags, context)

	crl.SetArgs(make([]string, 0))

	crl.Flags().Set("update", "true")
	err := crl.Execute()
	if err != nil {
		return errors.Wrap(err, "Error updating CRL")
	}

	return nil
}

func (cmd CommandCRL) Do() (error) {
	dk := GetConfigDK(cmd.config)

	path := cmd.flags.GetString("path")

	if cmd.update {
		err := CreateCRL(path, cmd.duration, dk)
		if err != nil {
			return errors.Wrap(err, "Error creating CRL")
		}
	} else if cmd.export {
		err := ExportCRL(path, "pem", cmd.outputDir, cmd.context, dk)
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
			context: ctx,
		}, ctx),
	}

	cmd.Flags().Bool("update", false, "Update Certificate Revocation List")
	cmd.Flags().Bool("export", false, "Export Certificate Revocation List")
	cmd.Flags().StringP("output-dir", "o", "", "Output to directory. Filename will be auto-generated")
	cmd.Flags().StringP("duration", "d", "3600", "Set the validity of the CRL in second. Support arithmetic operations")

	flags.BindPFlags(cmd.Flags())

	return cmd
}
