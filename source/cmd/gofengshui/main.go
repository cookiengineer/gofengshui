package main

import (
	"os"

	"gofengshui/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
