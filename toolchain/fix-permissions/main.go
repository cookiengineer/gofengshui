package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gofengshui/toolchain/internal/execx"
	"gofengshui/toolchain/internal/repo"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fix-permissions:", err)
		os.Exit(1)
	}
}

func run() error {
	var paths stringList
	uid := flag.Int("uid", -1, "target user ID")
	gid := flag.Int("gid", -1, "target group ID")
	dryRun := flag.Bool("dry-run", false, "print the paths and ownership without changing files")
	flag.Var(&paths, "path", "path to chown recursively; may be repeated")
	flag.Parse()

	root, err := repo.Root()
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		paths = append(paths, "build")
	}
	absolute := make([]string, 0, len(paths))
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		absolute = append(absolute, filepath.Clean(path))
	}
	targetUID, targetGID := *uid, *gid
	if targetUID < 0 {
		targetUID = currentID("SUDO_UID", os.Getuid())
	}
	if targetGID < 0 {
		targetGID = currentID("SUDO_GID", os.Getgid())
	}

	runner := execx.New()
	runner.DryRun = *dryRun
	if *dryRun {
		for _, path := range absolute {
			fmt.Printf("chown %s %d:%d\n", displayPath(root, path), targetUID, targetGID)
		}
		return nil
	}
	if os.Geteuid() != 0 {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		args := []string{
			executable,
			"--uid", strconv.Itoa(targetUID),
			"--gid", strconv.Itoa(targetGID),
		}
		for _, path := range absolute {
			args = append(args, "--path", path)
		}
		name, sudoArgs := execx.Sudo(executable, args[1:]...)
		return runner.Replace(root, name, sudoArgs...)
	}
	for _, path := range absolute {
		if err := chownTree(path, targetUID, targetGID); err != nil {
			return err
		}
		fmt.Printf("restored ownership of %s to %d:%d\n", displayPath(root, path), targetUID, targetGID)
	}
	return nil
}

func currentID(env string, fallback int) int {
	if value := os.Getenv(env); value != "" {
		if id, err := strconv.Atoi(value); err == nil {
			return id
		}
	}
	return fallback
}

func chownTree(path string, uid, gid int) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	return filepath.WalkDir(path, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(name, uid, gid)
	})
}

func displayPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return path
	}
	return rel
}
