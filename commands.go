package main

import (
	"github.com/tehmoon/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/abiosoft/ishell"
)

var (
	ErrBadPassword = errors.New("Password is either wrong or database is corrupted")
	ErrEmptyPassword = errors.New("Password is empty")
	ErrCorruptedPasswordFile = errors.New("Password file is corrupted")
	ErrCorruptedFile = errors.New("File is corrupted")
	ErrCommandUnsupportedPrivateKey = errors.New("")
	ErrCommandNoCommandSpecified = errors.New("No command specified")
	ErrCommandNotSupported = errors.New("Command not supported")
	ErrCommandAlreadyConfigured = errors.New("Command has already been configured")
	ErrCommandBadFlags = errors.New("")
	ErrCommandDirectoryNotEmpty = errors.New("Target directory is not empty")
	ErrCommandDirectoryAlreadyExists = errors.New("Directory already exists")
	ErrFileAlreadyExists = errors.New("File already exists")
	ErrFileNotFound = errors.New("File not found")
	ErrCommandNegativeDuration = errors.New("Duration cannot be negative")
	ErrCommandNotDirectory = errors.New("Not a directory")
	ErrCommandDirectoryNotInit = errors.New("Directory has not been initialized. Call init first")
)

type Command interface {
	Do() (error)
	Init(*flag.FlagSet, []string) (error)
	Config() (*viper.Viper)
	Flags() (*viper.Viper)
}

var (
	CommandsFunc = []func(*viper.Viper, *viper.Viper, *ishell.Context) (*cobra.Command) {
		NewCommandCreateCA,
		NewCommandCreate,
		NewCommandExport,
		NewCommandInit,
		NewCommandRevoke,
		NewCommandCRL,
	}
)
