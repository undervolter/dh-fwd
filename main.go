package main

import (
	"dh-fwd/core"
)

var Version = "v2.4.1"

func main() {
	if Version != "" {
		core.Version = Version
	}
	core.Execute()
}
