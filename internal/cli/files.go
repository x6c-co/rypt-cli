package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// openInput opens the input named on the command line. An empty name or
// "-" is stdin, returned with a nil *os.File. A directory is a usage error.
func openInput(env Env, name string) (io.Reader, *os.File, error) {
	if name == "" || name == "-" {
		return env.Stdin, nil, nil
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, ioError(err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, ioError(err)
	}
	if fi.IsDir() {
		f.Close()
		return nil, nil, usageErrorf("%s is a directory; archive it first, for example with tar", name)
	}
	return f, f, nil
}

// checkOutput refuses an output path that is the input file, or that exists
// when force is false. in is the open input file, or nil for stdin.
func checkOutput(inName string, in *os.File, out string, force bool) error {
	if in != nil {
		absIn, err1 := filepath.Abs(inName)
		absOut, err2 := filepath.Abs(out)
		if err1 == nil && err2 == nil && absIn == absOut {
			return refusef("refusing to write the output over the input %s", inName)
		}
		inInfo, err1 := in.Stat()
		outInfo, err2 := os.Stat(out)
		if err1 == nil && err2 == nil && os.SameFile(inInfo, outInfo) {
			return refusef("refusing to write the output over the input %s", inName)
		}
	}
	// A device, FIFO or socket, or a symlink to one, is not a file that can
	// be replaced: --force would rename a regular file over it.
	if st, err := os.Stat(out); err == nil && !st.Mode().IsRegular() && !st.IsDir() {
		return usageErrorf("the output %s is not a regular file; use -o - and redirect stdout to it", out)
	}
	fi, err := os.Lstat(out)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return ioError(err)
	case fi.IsDir():
		return usageErrorf("the output %s is a directory", out)
	case !force:
		return refusef("refusing to replace the existing file %s; use --force to replace it", out)
	}
	return nil
}

// checkStdout refuses to write to stdout when stdout is the input file, as in
// "rypt decrypt -o - f.rypt >> f.rypt". in is the open input file, or nil for
// stdin. Only a regular file can be both, so terminals and pipes pass.
func checkStdout(env Env, inName string, in *os.File) error {
	out, ok := env.Stdout.(*os.File)
	if !ok {
		return nil
	}
	if in == nil {
		if in, ok = env.Stdin.(*os.File); !ok {
			return nil
		}
	}
	outInfo, err := out.Stat()
	if err != nil || !outInfo.Mode().IsRegular() {
		return nil
	}
	inInfo, err := in.Stat()
	if err != nil || !os.SameFile(inInfo, outInfo) {
		return nil
	}
	return refusef("refusing to write the output over the input %s", describe(inName))
}

// tempFile is a temporary file in the destination directory that becomes
// the output once it is complete.
type tempFile struct {
	*os.File
	dest  string
	force bool
	done  bool
}

// createTemp creates the temporary file for dest in dest's directory, with
// mode 0600.
func createTemp(dest string, force bool) (*tempFile, error) {
	dir := filepath.Dir(dest)
	// The name leaves out dest's base name, which may already be near the
	// file system's name length limit.
	f, err := os.CreateTemp(dir, ".rypt-*.tmp")
	if err != nil {
		return nil, ioError(err)
	}
	trackTemp(f)
	return &tempFile{File: f, dest: dest, force: force}, nil
}

// commit syncs and closes the temporary file and moves it into place.
// Without force, an existing file is never replaced: the temporary file is
// hard-linked to the destination, which fails if the destination exists.
// With force, it is renamed over the destination.
func (t *tempFile) commit() error {
	if err := t.Sync(); err != nil {
		return ioError(err)
	}
	if err := t.Close(); err != nil {
		return ioError(err)
	}
	tmp := t.Name()
	if t.force {
		if err := os.Rename(tmp, t.dest); err != nil {
			return ioError(err)
		}
		t.done = true
		untrackTemp(t.File)
		return nil
	}
	err := os.Link(tmp, t.dest)
	if errors.Is(err, fs.ErrExist) {
		return refusef("refusing to replace the existing file %s; use --force to replace it", t.dest)
	}
	if err != nil {
		// Some file systems, such as FAT, have no hard links. Copy into a
		// newly created file instead, which also never replaces one.
		if err := copyExclusive(tmp, t.dest); err != nil {
			return err
		}
	}
	t.done = true
	untrackTemp(t.File)
	os.Remove(tmp)
	return nil
}

// discard removes the temporary file unless it was committed.
func (t *tempFile) discard() {
	if t == nil || t.done {
		return
	}
	t.Close()
	os.Remove(t.Name())
	untrackTemp(t.File)
}

// copyExclusive copies src to a new file dst, failing if dst exists.
func copyExclusive(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return ioError(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return refusef("refusing to replace the existing file %s; use --force to replace it", dst)
	}
	if err != nil {
		return ioError(err)
	}
	// Until the copy is complete, dst is as incomplete as a temporary file:
	// track it so that RemoveTempFiles deletes it after an interrupt.
	trackTemp(out)
	defer untrackTemp(out)
	defer func() {
		if err != nil {
			os.Remove(dst)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return ioError(err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return ioError(err)
	}
	if err := out.Close(); err != nil {
		return ioError(err)
	}
	return nil
}

// Temporary files are tracked so that RemoveTempFiles can delete them when
// the process is interrupted while Run is still working.
var (
	tempMu    sync.Mutex
	tempFiles = map[*os.File]struct{}{}
)

func trackTemp(f *os.File) {
	tempMu.Lock()
	tempFiles[f] = struct{}{}
	tempMu.Unlock()
}

func untrackTemp(f *os.File) {
	tempMu.Lock()
	delete(tempFiles, f)
	tempMu.Unlock()
}

// RemoveTempFiles closes and removes every temporary file that Run has
// created and not yet moved into place or removed. The entry point calls it
// when the process is interrupted and Run does not return promptly.
func RemoveTempFiles() {
	tempMu.Lock()
	defer tempMu.Unlock()
	for f := range tempFiles {
		f.Close()
		os.Remove(f.Name())
		delete(tempFiles, f)
	}
}

// ctxReader returns ctx's error instead of reading once ctx is done, so that
// an interrupt stops a long encryption or decryption between reads.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// describe returns a short name for an input or output path for messages.
func describe(name string) string {
	if name == "" || name == "-" {
		return "stdin"
	}
	return fmt.Sprintf("%q", name)
}
