package main

import (
	"dh-fwd/core"
)

var Version = "0.2"

func main() {
	if Version != "" {
		core.Version = Version
	}
	core.Execute()
}
