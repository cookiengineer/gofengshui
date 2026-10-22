package main

import (
	"os"

	"gofengshui/source/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
