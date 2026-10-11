// Command rypt encrypts and decrypts files with envelope encryption: a new
// data key per file, wrapped by a key held by the rypt API.
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/x6c-co/rypt-cli/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// interruptGrace is how long Run gets to clean up after an interrupt before
// the process removes its temporary files and exits anyway, for example
// while Run is blocked reading a terminal.
const interruptGrace = 2 * time.Second

func main() {
	// SIGHUP arrives when the terminal closes or an SSH session drops. Its
	// default action would kill the process without removing the temporary
	// file, which may hold decrypted data. Under nohup it stays ignored:
	// Notify would undo that.
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		sigs = append(sigs, syscall.SIGHUP)
	}
	ctx, stop := signal.NotifyContext(context.Background(), sigs...)

	done := make(chan int, 1)
	go func() {
		done <- cli.Run(ctx, cli.Env{
			Args:             os.Args[1:],
			Getenv:           os.Getenv,
			Stdin:            os.Stdin,
			Stdout:           os.Stdout,
			Stderr:           os.Stderr,
			StdoutIsTerminal: func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
			Version:          buildVersion(),
		})
	}()

	var code int
	select {
	case code = <-done:
	case <-ctx.Done():
		// A second signal ends the wait early. The handler stays installed,
		// so it cannot kill the process before the files are removed.
		again := make(chan os.Signal, 1)
		signal.Notify(again, sigs...)
		select {
		case code = <-done:
		case <-again:
			code = abandon()
		case <-time.After(interruptGrace):
			code = abandon()
		}
	}
	stop()
	os.Exit(code)
}

// abandon removes the temporary files of a Run that did not stop in time.
func abandon() int {
	cli.RemoveTempFiles()
	os.Stderr.WriteString("rypt: interrupted\n")
	return cli.ExitInterrupted
}

// buildVersion returns the version set with -ldflags, or else the module
// version that "go install ...@version" records in the binary.
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}
