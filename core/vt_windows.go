//go:build windows

package core

import (
	"os"

	"golang.org/x/sys/windows"
)

func initTerminal() {
	handleOut := windows.Handle(os.Stdout.Fd())
	var modeOut uint32
	if err := windows.GetConsoleMode(handleOut, &modeOut); err == nil {
		_ = windows.SetConsoleMode(handleOut, modeOut|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
	handleErr := windows.Handle(os.Stderr.Fd())
	var modeErr uint32
	if err := windows.GetConsoleMode(handleErr, &modeErr); err == nil {
		_ = windows.SetConsoleMode(handleErr, modeErr|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}
