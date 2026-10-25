package repo

import (
	"fmt"
	"os"
	"path/filepath"
)

func Root() (string, error) {
	if root := os.Getenv("GFS_REPO_ROOT"); root != "" {
		return filepath.Abs(root)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "source", "go.mod")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", fmt.Errorf("repository root not found; set GFS_REPO_ROOT")
		}
		wd = parent
	}
}
