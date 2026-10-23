package main

import (
	"dh-fwd/core"
)

var Version = "v2.5.0"

func main() {
	if Version != "" {
		core.Version = Version
	}
	core.Execute()
}
