package main

import (
	"strings"
	"github.com/tehmoon/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/abiosoft/ishell"
)

type CommandExport struct {
	flags *viper.Viper
	config *viper.Viper
	name string
	format string
	priv bool
	ctx *ishell.Context
}

func (cmd CommandExport) Config() (*viper.Viper) {
	return cmd.config
}

func (cmd CommandExport) Flags() (*viper.Viper) {
	return cmd.flags
}

func (cmd *CommandExport) Init(set *flag.FlagSet, args []string) (error) {
	cmd.name = cmd.flags.GetString("name")
	if cmd.name == "" {
		return errors.Wrap(ErrCommandBadFlags, "Name flag cannot be empty")
	}

	cmd.format = cmd.flags.GetString("format")
	err := parseCommandExportFormat(cmd.format)
	if err != nil {
		return errors.Wrapf(err, "Error parsing format %q", cmd.format)
	}

	cmd.priv = cmd.flags.GetBool("priv")

	return nil
}

func (cmd CommandExport) Do() (error) {
	path := cmd.flags.GetString("path")
	dk := GetConfigDK(cmd.config)

	if ! cmd.priv {
		err := ExportCertificate(path, cmd.name, cmd.format, cmd.ctx, dk)
		if err != nil {
			return errors.Wrapf(err, "Error exporting the certificate of %q", cmd.name)
		}
	} else {
		err := ExportPrivateKey(path, cmd.name, cmd.format, cmd.ctx, dk)
		if err != nil {
			return errors.Wrapf(err, "Error exporting the private key of %q", cmd.name)
		}
	}

	return nil
}

func NewCommandExport(config, flags *viper.Viper, ctx *ishell.Context) (*cobra.Command) {
	cmd := &cobra.Command{
		Use: "export",
		Args: cobra.ExactArgs(0),
		RunE: ExecuteCommand(&CommandExport{
			flags: flags,
			config: config,
			ctx: ctx,
		}, ctx),
	}

	cmd.Flags().StringP("name", "n", "", "Common Name to export. For CA use \"ca\".")
	cmd.Flags().StringP("format", "f", "pem", "Default output format. Valid are: ['pem']")
	cmd.Flags().Bool("priv", false, "Export the private key instead")

	cmd.MarkFlagRequired("name")

	flags.BindPFlags(cmd.Flags())

	return cmd
}

func parseCommandExportFormat(format string) (error) {
	format = strings.ToLower(format)

	switch format {
		case "pem":
		default:
			return errors.New("Bad format")
	}

	return nil
}
