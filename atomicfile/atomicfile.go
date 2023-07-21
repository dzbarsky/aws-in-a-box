package atomicfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Write ensures that the data from `r` is either written fully to filename, or errors.
// It returns the number of bytes written, or an error.
func Write(filename string, r io.Reader, perm os.FileMode) (n int64, err error) {
	fi, err := os.Stat(filename)
	if err == nil && !fi.Mode().IsRegular() {
		return 0, fmt.Errorf("%s already exists and is not a regular file", filename)
	}

	// tempfile must be in the same volume to ensure rename is atomic!
	f, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return 0, err
	}
	tmpName := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmpName)
		}
	}()
	n, err = io.Copy(f, r)
	if err != nil {
		return 0, err
	}
	if runtime.GOOS != "windows" {
		if err := f.Chmod(perm); err != nil {
			return 0, err
		}
	}
	// Need an fsync; otherwise it's valid for filesystems to end up with a
	// 0-length file post-rename.
	if err := f.Sync(); err != nil {
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	err = os.Rename(tmpName, filename)
	return n, err
}
