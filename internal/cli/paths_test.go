package cli

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecryptNaming covers the .rypt suffix rules of spec §4.
func TestDecryptNaming(t *testing.T) {
	t.Parallel()
	pt := []byte("suffix rules\n")

	t.Run("FILE.rypt writes FILE", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		ct := h.encryptFixture("report.pdf.rypt", pt)
		h.writeFile("dir/report.pdf.rypt", ct)
		expect(t, h.run("decrypt", h.path("dir", "report.pdf.rypt")), ExitOK)
		h.assertEntries("dir", "report.pdf", "report.pdf.rypt")
		h.assertContent("dir/report.pdf", pt)
	})

	t.Run("only the last suffix is removed", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.encryptFixture("x.rypt.rypt", pt)
		expect(t, h.run("decrypt", h.path("x.rypt.rypt")), ExitOK)
		h.assertEntries("", "x.rypt", "x.rypt.rypt")
		h.assertContent("x.rypt", pt)
	})

	t.Run("encrypt FILE.rypt writes FILE.rypt.rypt", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.writeFile("y.rypt", pt)
		expect(t, h.run("encrypt", h.path("y.rypt")), ExitOK)
		h.assertEntries("", "y.rypt", "y.rypt.rypt")
	})

	// A FILE without the suffix needs -o; without it, exit 2 before any
	// API call and nothing is written.
	for _, name := range []string{"noext", "x.RYPT", "x.Rypt", "x.ryp", "x.rypt.bak", "xrypt", "sub/.rypt", ".rypt"} {
		t.Run("no suffix "+name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			ct := h.encryptFixture("fixture.bin", pt)
			h.writeFile(name, ct)
			dir := filepath.Dir(name)
			before := entries(t, h.path(dir))

			res := h.run("decrypt", h.path(name))
			expect(t, res, ExitUsage)
			h.wantCalls(1, 0)
			h.assertEntries(dir, before...)

			// With -o it works.
			expect(t, h.run("decrypt", "-o", h.path("out.txt"), h.path(name)), ExitOK)
			h.assertContent("out.txt", pt)
			h.wantCalls(1, 1)
		})
	}

	t.Run("no suffix and missing", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		res := h.run("decrypt", h.path("does-not-exist"))
		if res.code != ExitUsage && res.code != ExitIO {
			t.Errorf("exit %d, want 2 (needs -o) or 3 (missing)", res.code)
		}
		h.wantCalls(0, 0)
	})
}

// TestRelativePaths runs with relative names from the working directory.
func TestRelativePaths(t *testing.T) {
	h := newHarness(t)
	t.Chdir(h.dir)
	pt := []byte("relative\n")
	h.writeFile("rel.txt", pt)
	expect(t, h.run("encrypt", "rel.txt"), ExitOK)
	h.assertEntries("", "rel.txt", "rel.txt.rypt")
	if err := os.Remove("rel.txt"); err != nil {
		t.Fatal(err)
	}
	expect(t, h.run("decrypt", "rel.txt.rypt"), ExitOK)
	h.assertContent("rel.txt", pt)

	// The same file under another spelling is still the input.
	for _, args := range [][]string{
		{"encrypt", "-o", "./rel.txt", "rel.txt"},
		{"encrypt", "-f", "-o", "rel.txt", "./rel.txt"},
		{"encrypt", "-f", "-o", filepath.Join(h.dir, "rel.txt"), "rel.txt"},
		{"decrypt", "-f", "-o", "./rel.txt.rypt", "rel.txt.rypt"},
	} {
		res := h.run(args...)
		if res.code != ExitUsage {
			t.Errorf("rypt %q: exit %d, want 2\n%s", args, res.code, res.stderr)
		}
	}
	h.assertContent("rel.txt", pt)
	h.wantCalls(1, 1)
	h.assertEntries("", "rel.txt", "rel.txt.rypt")

	// A file named just ".rypt" has no name left once the suffix is
	// removed: it needs -o, like any FILE without the suffix.
	ct := h.readFile("rel.txt.rypt")
	h.writeFile(".rypt", ct)
	for _, name := range []string{".rypt", "./.rypt"} {
		res := h.run("decrypt", name)
		if res.code != ExitUsage {
			t.Errorf("rypt decrypt %s: exit %d, want 2\n%s", name, res.code, res.stderr)
		}
	}
	h.wantCalls(1, 1)
	expect(t, h.run("decrypt", "-o", "dot.out", ".rypt"), ExitOK)
	h.assertContent("dot.out", pt)
	h.assertEntries("", "rel.txt", "rel.txt.rypt", ".rypt", "dot.out")
}

func entries(t testing.TB, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// TestOverwriteRefusal: an existing output is never replaced without
// --force, and the check comes before any API call.
func TestOverwriteRefusal(t *testing.T) {
	t.Parallel()
	existing := []byte("precious existing content")
	pt := []byte("new plaintext")

	type tc struct {
		name  string
		setup func(h *harness, ct []byte) // creates the input and the existing output
		args  func(h *harness) []string
		stdin func(ct []byte) []byte
	}
	cases := []tc{
		{"encrypt FILE to FILE.rypt", func(h *harness, ct []byte) {
			h.writeFile("in", pt)
			h.writeFile("in.rypt", existing)
		}, func(h *harness) []string { return []string{"encrypt", h.path("in")} }, nil},
		{"encrypt FILE -o", func(h *harness, ct []byte) { h.writeFile("in", pt); h.writeFile("out", existing) },
			func(h *harness) []string { return []string{"encrypt", "-o", h.path("out"), h.path("in")} }, nil},
		{"encrypt stdin -o", func(h *harness, ct []byte) { h.writeFile("out", existing) },
			func(h *harness) []string { return []string{"encrypt", "-o", h.path("out")} },
			func([]byte) []byte { return pt }},
		{"decrypt FILE.rypt to FILE", func(h *harness, ct []byte) {
			h.writeFile("in.rypt", ct)
			h.writeFile("in", existing)
		}, func(h *harness) []string { return []string{"decrypt", h.path("in.rypt")} }, nil},
		{"decrypt FILE -o", func(h *harness, ct []byte) { h.writeFile("in.rypt", ct); h.writeFile("out", existing) },
			func(h *harness) []string { return []string{"decrypt", "-o", h.path("out"), h.path("in.rypt")} }, nil},
		{"decrypt stdin -o", func(h *harness, ct []byte) { h.writeFile("out", existing) },
			func(h *harness) []string { return []string{"decrypt", "-o", h.path("out")} },
			func(ct []byte) []byte { return ct }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			// Build the ciphertext without API calls so the counts start at 0.
			ct, _ := h.craft(cipherAES, 65536, "", pt)
			c.setup(h, ct)
			args := c.args(h)
			outName := "out"
			if !strings.Contains(strings.Join(args, " "), "-o") {
				if args[0] == "encrypt" {
					outName = "in.rypt"
				} else {
					outName = "in"
				}
			}
			var stdin []byte
			if c.stdin != nil {
				stdin = c.stdin(ct)
			}
			before := entries(t, h.dir)

			res := h.runIn(stdin, args...)
			expect(t, res, ExitUsage)
			h.wantCalls(0, 0)
			h.assertContent(outName, existing)
			h.assertEntries("", before...)

			// --force (and -f) replace it.
			for i, force := range []string{"--force", "-f"} {
				var stdin []byte
				if c.stdin != nil {
					stdin = c.stdin(ct)
				}
				fargs := append([]string{args[0], force}, args[1:]...)
				res = h.runIn(stdin, fargs...)
				expect(t, res, ExitOK)
				h.assertMode0600(outName)
				h.assertEntries("", before...)
				if args[0] == "encrypt" {
					h.verifyEncrypted(h.readFile(outName), cipherAES, testKeyID, "")
					h.wantCalls(i+1, 0)
				} else {
					h.assertContent(outName, pt)
					h.wantCalls(0, i+1)
				}
			}
		})
	}
}

// TestForceReplacesPermissiveFile: a replaced file ends up with mode 0600,
// not the mode of the file it replaced.
func TestForceReplacesPermissiveFile(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile("in", []byte("abc"))
	h.writeFile("in.rypt", []byte("old"))
	if err := os.Chmod(h.path("in.rypt"), 0o666); err != nil {
		t.Fatal(err)
	}
	expect(t, h.run("encrypt", "-f", h.path("in")), ExitOK)
	h.assertMode0600("in.rypt")
}

// TestOutputIsDirectory: an existing directory as the output is a usage
// error, with or without --force, before any API call.
func TestOutputIsDirectory(t *testing.T) {
	t.Parallel()
	for _, force := range []bool{false, true} {
		h := newHarness(t)
		ct, _ := h.craft(cipherAES, 65536, "", []byte("x"))
		h.writeFile("in", []byte("x"))
		h.writeFile("d/keep", []byte("k"))
		h.writeFile("in.rypt/keep", []byte("k")) // encrypt in -> in.rypt, a directory
		h.writeFile("c.rypt", ct)
		h.writeFile("c/keep", []byte("k")) // decrypt c.rypt -> c, a directory
		f := []string{}
		if force {
			f = []string{"-f"}
		}
		for _, args := range [][]string{
			{"encrypt", "-o", h.path("d"), h.path("in")},
			{"encrypt", h.path("in")},
			{"encrypt", "-o", h.path("d") + string(filepath.Separator)},
			{"decrypt", "-o", h.path("d"), h.path("c.rypt")},
			{"decrypt", h.path("c.rypt")},
		} {
			args = append(args[:1:1], append(f, args[1:]...)...)
			res := h.runIn([]byte("x"), args...)
			if res.code != ExitUsage {
				t.Errorf("rypt %q: exit %d, want 2\n%s", args, res.code, res.stderr)
			}
		}
		h.wantCalls(0, 0)
		h.assertEntries("d", "keep")
		h.assertEntries("in.rypt", "keep")
		h.assertEntries("c", "keep")
	}
}

// TestInputEqualsOutput: rypt refuses to write over its input, through any
// name for the same file, even with --force, before any API call.
func TestInputEqualsOutput(t *testing.T) {
	t.Parallel()
	for _, force := range []bool{false, true} {
		h := newHarness(t)
		pt := []byte("the input")
		ct, _ := h.craft(cipherAES, 65536, "", pt)
		h.writeFile("a", pt)
		h.writeFile("b.rypt", ct)
		mustLink(t, h.path("a"), h.path("a-hard"))
		mustLink(t, h.path("b.rypt"), h.path("b")) // decrypt b.rypt -> b, the same file
		symlinks := trySymlink(h.path("a"), h.path("a-sym"))
		if symlinks {
			trySymlink(h.path("b.rypt"), h.path("b-sym"))
			trySymlink(h.path("a"), h.path("a.rypt")) // encrypt a -> a.rypt, a link to a
		}

		var f []string
		if force {
			f = []string{"--force"}
		}
		cases := [][]string{
			{"encrypt", "-o", h.path("a"), h.path("a")},
			{"encrypt", "-o", h.path("sub", "..", "a"), h.path("a")},
			{"encrypt", "-o", h.path("a-hard"), h.path("a")},
			{"encrypt", "-o", h.path("a"), h.path("a-hard")},
			{"decrypt", "-o", h.path("b.rypt"), h.path("b.rypt")},
			{"decrypt", h.path("b.rypt")},
		}
		if symlinks {
			cases = append(cases,
				[]string{"encrypt", "-o", h.path("a-sym"), h.path("a")},
				[]string{"encrypt", "-o", h.path("a"), h.path("a-sym")},
				[]string{"encrypt", h.path("a")},
				[]string{"decrypt", "-o", h.path("b-sym"), h.path("b.rypt")},
			)
		}
		if err := os.Mkdir(h.path("sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		before := entries(t, h.dir)
		for _, args := range cases {
			args = append(args[:1:1], append(f, args[1:]...)...)
			res := h.run(args...)
			if res.code != ExitUsage {
				t.Errorf("rypt %q: exit %d, want 2\n%s", args, res.code, res.stderr)
			}
		}
		h.wantCalls(0, 0)
		h.assertContent("a", pt)
		h.assertContent("b.rypt", ct)
		h.assertEntries("", before...)
	}
}

func mustLink(t testing.TB, oldname, newname string) {
	t.Helper()
	if err := os.Link(oldname, newname); err != nil {
		t.Skipf("hard links not supported: %v", err)
	}
}

func trySymlink(oldname, newname string) bool {
	return os.Symlink(oldname, newname) == nil
}

// TestOutputSymlink: an output name that is a symbolic link is an existing
// file. Without --force nothing is written through it; with --force the
// link itself is replaced and its target is left alone.
func TestOutputSymlink(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile("in", []byte("data"))
	h.writeFile("target", []byte("target content"))
	if !trySymlink(h.path("target"), h.path("in.rypt")) || !trySymlink(h.path("nowhere"), h.path("dangling")) {
		t.Skip("symbolic links not supported")
	}

	expect(t, h.run("encrypt", h.path("in")), ExitUsage)
	expect(t, h.run("encrypt", "-o", h.path("dangling"), h.path("in")), ExitUsage)
	h.wantCalls(0, 0)
	h.assertMissing("nowhere")
	h.assertContent("target", []byte("target content"))

	expect(t, h.run("encrypt", "-f", h.path("in")), ExitOK)
	expect(t, h.run("encrypt", "-f", "-o", h.path("dangling"), h.path("in")), ExitOK)
	h.wantCalls(2, 0)
	h.assertContent("target", []byte("target content"))
	h.assertMissing("nowhere")
	h.assertMode0600("in.rypt")
	h.assertMode0600("dangling")
	h.verifyEncrypted(h.readFile("in.rypt"), cipherAES, testKeyID, "")
}

// TestInputErrors: a directory is a usage error, a missing file an I/O
// error, and an output directory that does not exist is an I/O error, all
// before any API call.
func TestInputErrors(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile("dir/keep", nil)
	h.writeFile("dir.rypt/keep", nil)
	h.writeFile("in", []byte("x"))
	ct, _ := h.craft(cipherAES, 65536, "", []byte("x"))
	h.writeFile("c.rypt", ct)

	cases := []struct {
		args []string
		code int
	}{
		{[]string{"encrypt", h.path("dir")}, ExitUsage},
		{[]string{"encrypt", "-o", h.path("o.rypt"), h.path("dir")}, ExitUsage},
		{[]string{"decrypt", h.path("dir.rypt")}, ExitUsage},
		{[]string{"decrypt", "-o", h.path("o"), h.path("dir")}, ExitUsage},
		{[]string{"encrypt", h.path("missing")}, ExitIO},
		{[]string{"encrypt", "-o", h.path("o.rypt"), h.path("missing")}, ExitIO},
		{[]string{"decrypt", h.path("missing.rypt")}, ExitIO},
		{[]string{"decrypt", "-o", h.path("o"), h.path("missing")}, ExitIO},
		{[]string{"encrypt", "-o", h.path("nodir", "o.rypt"), h.path("in")}, ExitIO},
		{[]string{"encrypt", "-o", h.path("nodir", "o.rypt")}, ExitIO},
		{[]string{"decrypt", "-o", h.path("nodir", "o"), h.path("c.rypt")}, ExitIO},
		{[]string{"encrypt", "-o", h.path("in", "o.rypt"), h.path("c.rypt")}, ExitIO}, // a file as a directory
	}
	for _, c := range cases {
		res := h.runIn([]byte("x"), c.args...)
		if res.code != c.code {
			t.Errorf("rypt %q: exit %d, want %d\n%s", c.args, res.code, c.code, res.stderr)
		}
	}
	h.wantCalls(0, 0)
	h.assertEntries("", "dir", "dir.rypt", "in", "c.rypt")
}

// TestOutputAppearsDuringAPICall: a file that appears at the output path
// after the existence check is still never replaced without --force (spec
// §6 step 6, the hard link), and is replaced with --force.
func TestOutputAppearsDuringAPICall(t *testing.T) {
	t.Parallel()
	intruder := []byte("written by someone else meanwhile")

	for _, op := range []string{"wrap", "unwrap"} {
		for _, force := range []bool{false, true} {
			h := newHarness(t)
			pt := testData(200000, 3)
			ct, _ := h.craft(cipherXChaCha, 65536, "", pt)
			h.writeFile("in", pt)
			h.writeFile("c.rypt", ct)
			out := "in.rypt"
			args := []string{"encrypt", h.path("in")}
			if op == "unwrap" {
				out = "c"
				args = []string{"decrypt", h.path("c.rypt")}
			}
			if force {
				args = append(args, "--force")
			}
			h.api.setHook(func(string, *http.Request) {
				if err := os.WriteFile(h.path(out), intruder, 0o644); err != nil {
					t.Error(err)
				}
			})
			res := h.run(args...)
			if !force {
				expect(t, res, ExitUsage)
				h.assertContent(out, intruder)
			} else {
				expect(t, res, ExitOK)
				h.assertMode0600(out)
				if op == "wrap" {
					h.verifyEncrypted(h.readFile(out), cipherAES, testKeyID, "")
				} else {
					h.assertContent(out, pt)
				}
			}
			h.assertEntries("", "in", "c.rypt", out)
		}
	}
}

// TestCopyExclusive covers the commit fallback for file systems without
// hard links: it never replaces an existing file and creates mode 0600.
func TestCopyExclusive(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	data := testData(150000, 9)
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := copyExclusive(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("copy differs (err %v)", err)
	}
	assertMode0600(t, dst)

	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = copyExclusive(src, other)
	if exitCode(err) != ExitUsage {
		t.Errorf("copy over an existing file: %v (exit %d), want a refusal (exit 2)", err, exitCode(err))
	}
	if got, _ := os.ReadFile(other); string(got) != "keep" {
		t.Errorf("existing file changed to %q", got)
	}
	if err := copyExclusive(filepath.Join(dir, "missing"), filepath.Join(dir, "new")); exitCode(err) != ExitIO {
		t.Errorf("copy of a missing file: exit %d, want 3", exitCode(err))
	}
	if _, err := os.Stat(filepath.Join(dir, "new")); err == nil {
		t.Error("a failed copy left its output behind")
	}
}
