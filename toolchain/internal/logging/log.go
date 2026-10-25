package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Log struct {
	Path   string
	Writer io.Writer
	file   *os.File
}

func New(dir, prefix string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.log", prefix, time.Now().Format("20060102-150405")))
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err == nil {
		path = absolute
	}
	link := filepath.Join(dir, "latest-"+prefix+".log")
	_ = os.Remove(link)
	if err := os.Symlink(path, link); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Log{Path: path, Writer: file, file: file}, nil
}

func (l *Log) Close() error {
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}
