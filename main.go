package main

import (
	"dh-fwd/core"
)

var Version = "0.1"

func main() {
	if Version != "" {
		core.Version = Version
	}
	core.Execute()
}
