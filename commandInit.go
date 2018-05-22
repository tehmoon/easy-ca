package main

import (
	"path/filepath"
	flag "github.com/spf13/pflag"
	"github.com/tehmoon/errors"
	"github.com/spf13/cobra"
	"os"
	"github.com/spf13/viper"
	"github.com/abiosoft/ishell"
)

type CommandInit struct {
	password string
	flags *viper.Viper
	config *viper.Viper
}

func (cmd *CommandInit) Init(set *flag.FlagSet, args []string) (error) {
	path := cmd.flags.GetString("path")
	if len(args) == 1 {
		path = args[0]
	}

	err := InitDirectories(path)
	if err != nil {
		return err
	}

	return nil
}

func CheckInitDirectory(base string) (error) {
	d, err := os.Open(filepath.Join(base, ".easy-ca"))
	if err != nil {
		return err
	}
	defer d.Close()

	return nil
}

func InitDirectories(base string) (error) {
	err := createDirectory(base)
	if err != nil {
		return errors.Wrap(err, "Error creating base directory")
	}

	err = createDirectory(filepath.Join(base, "certificates"))
	if err != nil {
		return errors.Wrap(err, "Error creating certificates directory")
	}

	err = createDirectory(filepath.Join(base, "keys"))
	if err != nil {
		return errors.Wrap(err, "Error creating keys directory")
	}

	err = createDirectory(filepath.Join(base, "revoked"))
	if err != nil {
		return errors.Wrap(err, "Error creating revoked directory")
	}

	f, err := os.Create(filepath.Join(base, ".easy-ca"))
	if err != nil {
		return errors.Wrap(err, "Unable to create \".easy-ca\" file")
	}
	defer f.Close()

	return nil
}

func (cmd CommandInit) Config() (*viper.Viper) {
	return cmd.config
}

func (cmd CommandInit) Flags() (*viper.Viper) {
	return cmd.flags
}

func (cmd CommandInit) Do() (error) {
	path := cmd.flags.GetString("path")

	dk, err := InitPasswordFile(filepath.Join(path, ".pass"), cmd.config.GetString("password"))
	if err != nil {
		return errors.Wrap(err, "Error creating the \".pass\" file")
	}

	cmd.config.Set("key", dk)

	return nil
}

func NewCommandInit(config, flags *viper.Viper, ctx *ishell.Context) (*cobra.Command) {
	return &cobra.Command{
		Use: "init [path]",
		Args: cobra.MaximumNArgs(1),
		RunE: ExecuteCommand(&CommandInit{
			flags: flags,
			config: config,
		}, ctx),
	}
}
