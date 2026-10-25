package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"gofengshui/e2e/internal/hostinfo"
)

func main() {
	asJSON := flag.Bool("json", false, "print JSON instead of text")
	root := flag.String("root", "/", "filesystem root used to read proc and sys files")
	flag.Parse()

	info := hostinfo.Collect(*root)
	if !*asJSON {
		info.WriteText(os.Stdout)
		return
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(info); err != nil {
		fmt.Fprintln(os.Stderr, "hostinfo:", err)
		os.Exit(1)
	}
}
