package fs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

func FileExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !stat.IsDir(), nil
}

func DirectoryExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return stat.IsDir(), nil
}

func OpenFile(path string) (*os.File, error) {
	if _, statErr := os.Stat(path); errors.Is(statErr, fs.ErrNotExist) {
		return nil, fmt.Errorf("%v: %s", fs.ErrNotExist, path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}

	return file, nil
}

func MkdirIfNotExists(path string) error {
	if exists, err := DirectoryExists(path); err != nil {
		return fmt.Errorf("failed to stat directory: %v", err)
	} else if !exists {
		if err := os.Mkdir(path, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}
	return nil
}

func EnumerateDirectory(path string, action func(entry string)) error {
	if exists, err := DirectoryExists(path); err != nil {
		return fmt.Errorf("failed to stat directory: %v", err)
	} else if !exists {
		return fmt.Errorf("directory doesn't exist: %s", path)
	}

	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open directory: %v", err)
	}

	entries, err := dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("failed to enumerate directory: %v", err)
	}

	for _, entry := range entries {
		action(entry)
	}

	return nil
}
