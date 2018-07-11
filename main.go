package main

/*
	actions:
		- create new directory
		- create new CA with name
		- create certificates signed from CA
		- create CRL
		- import CA template
		- import cert template
		- revoke CA
		- revoke cert
		- list CA
		- list certs
		-	export CA cert
		- export cert cert
		- export cert private key
		- set/change config:
			- set default validity time for cert
		- git

	steps to phase1:
		- create directory if not exist
		- create CA and save ca.key.pem, ca.crt.pem
		- load ca.key.pem, ca.crt.pem when creating cert
		- save cert to issued/<name>.crt.pem
		- save key to private/<name>.key.pem
		- have a mandatory flag to set validity time
		- give a name for the certs -- CA/issued

	global-flags:
		- -path string: opt
	commands:
		- init:
			- path string: mandatory
		- create-ca:
			- -name string: mandatory
			- -valid-for duration: default 1 year
		- export:
			- -priv bool: default false
			- -name string: mandotary
			- -format string: default pem
		- create:
			- -name
			- -valid-for duration: default 3 month
*/

import (
	"fmt"
	"os"
	"github.com/tehmoon/errors"
	"github.com/spf13/cobra"
	"github.com/abiosoft/ishell"
	flag "github.com/spf13/pflag"
	"path/filepath"
	"github.com/spf13/viper"
)

func ExecuteCommand(command Command, ctx *ishell.Context) (func(cmd *cobra.Command, args []string) (error)) {
	return func(cmd *cobra.Command, args []string) (error) {
		err := command.Init(cmd.Flags(), args)
		if err != nil {
			return errors.Wrapf(err, "Error initializing %q command", cmd.Name())
		}

		config := command.Config()
		flags := command.Flags()

		path := config.GetString("path")
		if path == "" {
			path = flags.GetString("path")
			if path == "" {
				return errors.Wrap(ErrCommandBadFlags, "Path flag cannot be empty")
			}

			config.Set("path", path)
		}

		flags.Set("path", path)

		if key := config.Get("key"); key == nil {
			err = CheckInitDirectory(path)
			if err != nil {
				return errors.Wrapf(err, "Path %q doesn't seem to have been initialized. Use \"init\" first", path)
			}

			password := os.Getenv(flags.GetString("env-password"))
			if password == "" {
				if ctx == nil {
					return ErrEmptyPassword
				}

				for tries := 1; password == ""; tries++ {
					ctx.Print("Enter password: ")
					password = ctx.ReadPassword()

					if tries == 3 {
						return ErrEmptyPassword
					}
				}
			}

			config.Set("password", password)

			file := filepath.Join(flags.GetString("path"), ".pass")

			salt, dk, err := ReadPasswordFile(file)
			if err != nil {
				if cmd.Name() == "init" {
					return command.Do()
				}

				return errors.Wrap(err, "Error reading the password file")
			}

			err = VerifyPassword(password, salt, dk)
			if err != nil {
				return err
			}

			config.Set("key", dk)
		}

		return command.Do()
	}
}

func NewCompleter(set *flag.FlagSet) ([]string) {
	completer := []string{"--help",}

	set.VisitAll(func(f *flag.Flag) {
		completer = append(completer, fmt.Sprintf("--%s", f.Name))
	})

	return completer
}

func CompleterFunc(cmd *cobra.Command) (func([]string) ([]string)) {
	completer := NewCompleter(cmd.Flags())

	return func(args []string) ([]string) {
		if l := len(args); l > 0 {
			last := args[l-1]
			found := false

			cmd.Flags().VisitAll(func(f *flag.Flag) {
				if found {
					return
				}

				name := fmt.Sprintf("--%s", f.Name)

				if name == last {
					switch f.Value.Type() {
						case "bool":
							return
					}

					found = true
				}
			})

			if found {
				return []string{}
			}
		}

		return completer
	}
}

func PivotRootFunc(config *viper.Viper, cmd *cobra.Command, root *cobra.Command) (func(*ishell.Context)) {
	return func(ctx *ishell.Context) {
		pivotRoot := &cobra.Command{}
		pivotRoot.SetArgs(append([]string{cmd.Name(),}, ctx.Args...))

		for _, f := range CommandsFunc {
			flags := viper.New()

			flags.BindPFlags(root.PersistentFlags())

			pivotRoot.AddCommand(f(config, flags, ctx))
		}

		err := pivotRoot.Execute()
		if err != nil {
			ctx.Printf("err: %s\n", err.Error())
		}
	}
}

func StartInteractiveFunc(config *viper.Viper) (func(*cobra.Command, []string)) {
	return func(cmd *cobra.Command, args []string) {
		shell := ishell.New()
		shell.AutoHelp(false)

		for _, c := range cmd.Commands() {
			func(cmd *cobra.Command, root *cobra.Command) {
				icmd := &ishell.Cmd{
					Name: cmd.Name(),
					Completer: CompleterFunc(cmd),
					Func: PivotRootFunc(config, cmd, root),
				}

				shell.AddCmd(icmd)
			}(c, cmd)
		}

		shell.Run()
	}
}

func main() {
	config := viper.New()

	root := &cobra.Command{
		Use: fmt.Sprintf(os.Args[0]),
		Args: cobra.MaximumNArgs(1),
		Run: StartInteractiveFunc(config),
	}

	root.PersistentFlags().StringP("path", "p", "", "Path to the easy-ca directory database")
	root.PersistentFlags().StringP("env-password", "e", "", "Environment variable for password")

	LinkCobraViper(root, root.PersistentFlags(), config, CommandsFunc)

	err := root.Execute()
	if err != nil {
		panic(err)
	}
}

func LinkCobraViper(cmd *cobra.Command, set *flag.FlagSet, config *viper.Viper, cbs []func(*viper.Viper, *viper.Viper, *ishell.Context) (*cobra.Command)) {
	for _, cb := range cbs {
		flags := viper.New()

		flags.BindPFlags(set)

		cmd.AddCommand(cb(config, flags, nil))
	}
}
