// Package pass is a small, strictly non-interactive wrapper around the
// standard unix password manager CLI (`pass`).
//
// Listing is done by walking the password store directory (no decryption is
// needed for that), while every operation that touches the encrypted data goes
// through the `pass` binary. That way recipient handling, gpg agents, hooks and
// git integration stay exactly as the user configured them.
package pass

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultTimeout bounds a single `pass` invocation. Decrypting may block on a
// gpg pinentry dialog, so the value is deliberately generous.
const DefaultTimeout = 3 * time.Minute

// ErrNotFound is returned when a name does not exist in the store or the
// requested entry could not be decrypted because it is missing.
var ErrNotFound = errors.New("pass: запись не найдена")

// Entry is a single password store item.
type Entry struct {
	// Name is the path of the entry relative to the store root, without the
	// ".gpg" suffix, e.g. "cloud/aws/root".
	Name string
}

// Field is a "Key: value" line following the password line of an entry.
type Field struct {
	Key   string
	Value string
}

// Secret is the decrypted content of an entry.
type Secret struct {
	Name string
	// Password is the first line of the entry.
	Password string
	// Fields holds structured "Key: value" metadata.
	Fields []Field
	// Notes holds everything that is not the password and not a field.
	Notes string
	// Raw is the complete decrypted payload.
	Raw string
}

// Extra returns everything after the password line: the "Key: value" metadata
// and the free-form notes, exactly as stored. It is what the edit dialog puts
// into the "details" field.
func (s *Secret) Extra() string {
	body := strings.ReplaceAll(s.Raw, "\r\n", "\n")
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		return strings.TrimRight(body[i+1:], "\n")
	}
	return ""
}

// Store talks to a password store directory through the `pass` CLI.
type Store struct {
	// Binary is the absolute path to the pass executable.
	Binary string
	// Dir is the absolute path of the password store root.
	Dir string
	// Timeout is applied to every CLI call. Zero means DefaultTimeout.
	Timeout time.Duration
	Keyring *Keyring
}

// InitStore initializes a password-store directory with a .gpg-id file
// pointing to recipientID (fingerprint or key ID).
func InitStore(dir, recipientID string) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("путь к хранилищу не указан")
	}
	if strings.TrimSpace(recipientID) == "" {
		return errors.New("не указан идентификатор ключа для .gpg-id")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("не удалось создать каталог хранилища: %w", err)
	}
	gpgID := filepath.Join(dir, ".gpg-id")
	if err := os.WriteFile(gpgID, []byte(strings.TrimSpace(recipientID)+"\n"), 0o600); err != nil {
		return err
	}
	s := &Store{Dir: dir}
	s.gitCommitEntry(gpgID, "Set GPG id to "+strings.TrimSpace(recipientID)+".")
	return nil
}

func (s *Store) showEmbedded(name string) (*Secret, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	target := filepath.Join(s.Dir, filepath.FromSlash(name)+".gpg")
	cipher, err := os.ReadFile(target)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %w", name, err)
	}

	keys := s.Keyring.UnlockedKeys()
	if len(keys) == 0 {
		return nil, ErrLocked
	}

	var lastErr error
	for _, k := range keys {
		plain, err := DecryptBinary(cipher, k)
		if err == nil {
			return ParseSecret(name, string(plain)), nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrLocked
}

// gitCommitEntry stages target (including deletions) and commits it if s.Dir is
// inside a git repository and `git` is available.
func (s *Store) gitCommitEntry(target, message string) {
	dir := s.Dir
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addCmd := exec.CommandContext(ctx, gitBin, "-C", dir, "add", "-A")
	if err := addCmd.Run(); err != nil {
		return
	}

	commitCmd := exec.CommandContext(ctx, gitBin, "-C", dir,
		"-c", "user.name=go-pass",
		"-c", "user.email=go-pass@localhost",
		"commit", "-m", message)
	_ = commitCmd.Run()
}

func (s *Store) insertEmbedded(name, content string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if content == "" {
		return errors.New("содержимое записи пусто")
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	recipients, err := ResolveRecipients(s.Dir, name)
	if err != nil {
		return err
	}
	armors, err := s.Keyring.PublicArmors()
	if err != nil {
		return err
	}
	ring, err := BuildRecipientKeyRing(recipients, armors)
	if err != nil {
		return err
	}

	cipher, err := EncryptBinary([]byte(content), ring)
	if err != nil {
		return err
	}

	target := filepath.Join(s.Dir, filepath.FromSlash(name)+".gpg")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("не удалось создать подпапку: %w", err)
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, cipher, 0o600); err != nil {
		return fmt.Errorf("не удалось записать файл записи: %w", err)
	}
	return os.Rename(tmp, target)
	existed := false
	if _, statErr := os.Stat(target); statErr == nil {
		existed = true
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}
	action := "Add"
	if existed {
		action = "Edit"
	}
	s.gitCommitEntry(target, fmt.Sprintf("%s %s with go-pass.", action, name))
	return nil
}

func (s *Store) deleteEmbedded(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	target := filepath.Join(s.Dir, filepath.FromSlash(name)+".gpg")
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err := os.Remove(target); err != nil {
		return fmt.Errorf("не удалось удалить %s: %w", name, err)
	}
	s.pruneEmptyParents(target)
	return nil
	if err := os.Remove(target); err != nil {
		return fmt.Errorf("не удалось удалить %s: %w", name, err)
	}
	s.pruneEmptyParents(target)
	s.gitCommitEntry(target, fmt.Sprintf("Remove %s from store with go-pass.", name))
	return nil

}

// New discovers the `pass` binary and the password store directory.
func New() (*Store, error) {
	dir := os.Getenv("PASSWORD_STORE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("не удалось определить домашний каталог: %w", err)
		}
		dir = filepath.Join(home, ".password-store")
	} else {
		dir = expandHome(dir)
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("некорректный путь хранилища %q: %w", dir, err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("хранилище паролей не найдено: %s", abs)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("хранилище паролей не является каталогом: %s", abs)
	}

	binary, err := findPassBinary()
	if err != nil {
		return nil, err
	}

	return &Store{Binary: binary, Dir: abs, Timeout: DefaultTimeout}, nil
}

// DefaultStoreDir resolves the configured password store directory without
// requiring it to exist yet.
func DefaultStoreDir() (string, error) {
	dir := os.Getenv("PASSWORD_STORE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("не удалось определить домашний каталог: %w", err)
		}
		dir = filepath.Join(home, ".password-store")
	} else {
		dir = expandHome(dir)
	}
	return filepath.Abs(dir)
}

// IsInitialized reports whether s.Dir exists and contains a .gpg-id file
// (and, in embedded mode, that the keyring has a private key).
func (s *Store) IsInitialized() bool {
	if s == nil || s.Dir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(s.Dir, ".gpg-id")); err != nil {
		return false
	}
	if s.Keyring != nil && !s.Keyring.HasPrivateKey() {
		return false
	}
	return true
}

// / BackendMode selects how Store reads and writes encrypted entries.
type BackendMode string

const (
	BackendAuto     BackendMode = "auto"
	BackendCLI      BackendMode = "cli"
	BackendEmbedded BackendMode = "embedded"
)

// NewAuto resolves the Store backend according to mode ("auto", "cli", "embedded").
// In "auto" mode, an existing store with an installed `pass` CLI ALWAYS prefers
// the CLI backend so hooks, gpg-agent and git workflows are never silently bypassed.
func NewAuto(kr *Keyring, mode BackendMode) (*Store, error) {
	if mode == "" {
		mode = BackendAuto
	}
	abs, err := DefaultStoreDir()
	if err != nil {
		return nil, err
	}

	binary, cliErr := findPassBinary()
	_, gpgIDStat := os.Stat(filepath.Join(abs, ".gpg-id"))
	hasStore := gpgIDStat == nil

	switch mode {
	case BackendCLI:
		if cliErr != nil {
			return nil, cliErr
		}
		if !hasStore {
			return nil, fmt.Errorf("хранилище паролей не найдено: %s", abs)
		}
		return &Store{Binary: binary, Dir: abs, Timeout: DefaultTimeout}, nil

	case BackendEmbedded:
		if kr == nil {
			return nil, errors.New("встроенный режим требует инициализированный Keyring")
		}
		return &Store{Dir: abs, Timeout: DefaultTimeout, Keyring: kr}, nil

	case BackendAuto:
		// Если установлены CLI `pass` и хранилище уже инициализировано —
		// никогда не переключаемся тихо в embedded, даже если в keyring есть ключ.
		if cliErr == nil && hasStore {
			return &Store{Binary: binary, Dir: abs, Timeout: DefaultTimeout}, nil
		}
		if kr != nil {
			return &Store{Dir: abs, Timeout: DefaultTimeout, Keyring: kr}, nil
		}
		if cliErr != nil {
			return nil, cliErr
		}
		return nil, fmt.Errorf("хранилище паролей не найдено: %s", abs)

	default:
		return nil, fmt.Errorf("неизвестный режим хранилища: %q (ожидается auto, cli или embedded)", mode)
	}
}

// expandHome resolves a leading "~" in p.
func expandHome(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// findPassBinary looks for the pass CLI. GUI applications started from Finder
// usually get a minimal PATH that does not include Homebrew, so the common
// install locations are probed explicitly.
func findPassBinary() (string, error) {
	// An explicit override always wins, so the app can be pointed at a
	// specific pass install (or a test double).
	if override := os.Getenv("PASS_BINARY"); override != "" {
		if p, err := exec.LookPath(override); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("PASS_BINARY=%q указывает на несуществующий файл", override)
	}
	if p, err := exec.LookPath("pass"); err == nil {
		return p, nil
	}
	candidates := []string{
		"/opt/homebrew/bin/pass",
		"/usr/local/bin/pass",
		"/usr/bin/pass",
		"/home/linuxbrew/.linuxbrew/bin/pass",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".local", "bin", "pass"))
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", errors.New("не найден CLI pass (установите password-store или укажите PASS_BINARY)")
}

// env returns the environment for a CLI call: the inherited one plus the store
// directory (so `pass` always targets the store we list) and a PATH that also
// covers the usual user binary locations.
func (s *Store) env() []string {
	env := os.Environ()
	env = append(env, "PASSWORD_STORE_DIR="+s.Dir, "GIT_TERMINAL_PROMPT=0")

	path := os.Getenv("PATH")
	binDir := filepath.Dir(s.Binary)
	if !strings.Contains(":"+path+":", ":"+binDir+":") {
		path = binDir + ":" + path
	}
	return append(env, "PATH="+path)
}

// List returns every entry of the store sorted by name. Hidden files, the .git
// directory and non-.gpg files are skipped, matching what `pass ls` shows.
func (s *Store) List() ([]Entry, error) {
	entries := make([]Entry, 0, 64)
	root := s.Dir

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable subtree: skip it rather than failing the whole listing.
			if p == root {
				return err
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if p == root {
				return nil
			}
			if strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".gpg") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		entries = append(entries, Entry{Name: filepath.ToSlash(strings.TrimSuffix(rel, ".gpg"))})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать хранилище: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// Show decrypts an entry through `pass show`.
func (s *Store) Show(ctx context.Context, name string) (*Secret, error) {
	if s.Keyring != nil {
		return s.showEmbedded(name)
	}
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	stdout, stderr, err := s.run(ctx, nil, "show", name)
	if err != nil {
		return nil, s.cliError(err, stderr, "show "+name)
	}
	return ParseSecret(name, stdout), nil
}

// Insert stores content as a new entry, overwriting an existing one.
// The content must start with the password line.
func (s *Store) Insert(ctx context.Context, name, content string) error {
	if s.Keyring != nil {
		return s.insertEmbedded(name, content)
	}
	if err := ValidateName(name); err != nil {
		return err
	}
	content = normalizeContent(content)
	if content == "" {
		return errors.New("пустое содержимое записи")
	}

	target := filepath.Join(s.Dir, filepath.FromSlash(name)+".gpg")
	before, _ := os.Stat(target)

	_, stderr, err := s.run(ctx, strings.NewReader(content), "insert", "--multiline", "--force", name)
	if err == nil {
		return nil
	}

	// `pass insert` writes the encrypted file first and only then commits it to
	// git. A broken git identity therefore makes pass exit non-zero even though
	// the secret was stored. Report that as success with a warning instead of
	// telling the user the save failed.
	if after, statErr := os.Stat(target); statErr == nil && isFresh(before, after) && mentionsGit(stderr) {
		return nil
	}
	return s.cliError(err, stderr, "insert "+name)
}

// Delete removes an existing entry through `pass rm --force` and cleans up
// any empty parent directories left inside the store.
func (s *Store) Delete(ctx context.Context, name string) error {
	if s.Keyring != nil {
		return s.deleteEmbedded(name)
	}
	if err := ValidateName(name); err != nil {
		return err
	}

	target := filepath.Join(s.Dir, filepath.FromSlash(name)+".gpg")
	before, statErr := os.Stat(target)
	if os.IsNotExist(statErr) {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}

	_, stderr, err := s.run(ctx, nil, "rm", "--force", name)
	if err == nil {
		s.pruneEmptyParents(target)
		return nil
	}

	// `pass rm` removes the file first and only then commits the deletion to
	// git. If git fails (e.g. missing user.email) after the file is gone,
	// treat the deletion as successful, matching Insert().
	if before != nil && mentionsGit(stderr) {
		if _, afterErr := os.Stat(target); os.IsNotExist(afterErr) {
			s.pruneEmptyParents(target)
			return nil
		}
	}
	return s.cliError(err, stderr, "rm "+name)
}

// pruneEmptyParents removes empty ancestor directories of target up to (but
// excluding) s.Dir. os.Remove only succeeds on empty directories, so non-empty
// folders and the store root itself are never removed.
func (s *Store) pruneEmptyParents(target string) {
	root := filepath.Clean(s.Dir)
	for dir := filepath.Dir(target); dir != root && strings.HasPrefix(dir, root+string(filepath.Separator)); dir = filepath.Dir(dir) {
		if strings.HasPrefix(filepath.Base(dir), ".") {
			break
		}
		if err := os.Remove(dir); err != nil {
			break
		}
	}
}

// isFresh reports whether after was created or modified relative to before.
func isFresh(before, after os.FileInfo) bool {
	if after == nil {
		return false
	}
	if before == nil {
		return true
	}
	return !after.ModTime().Equal(before.ModTime())
}

func mentionsGit(stderr string) bool {
	s := strings.ToLower(stderr)
	hints := []string{
		"git",
		"author identity",
		"committer",
		"unable to auto-detect",
		"please tell me who you are",
	}
	for _, h := range hints {
		if strings.Contains(s, h) {
			return true
		}
	}
	return false
}

// run executes the pass CLI non-interactively. A nil stdin means the process
// gets no terminal input, so pass can never block on an interactive prompt.
func (s *Store) run(ctx context.Context, stdin *strings.Reader, args ...string) (stdout, stderr string, err error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var out, errBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, s.Binary, args...)
	cmd.Env = s.env()
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if stdin != nil {
		cmd.Stdin = stdin
	}

	err = cmd.Run()
	return out.String(), errBuf.String(), err
}

// cliError converts a process failure into a readable, actionable error.
func (s *Store) cliError(err error, stderr, what string) error {
	stderr = strings.TrimSpace(stderr)

	var exitErr *exec.ExitError
	code := -1
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("pass %s: превышено время ожидания (gpg не ответил)", what)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("pass %s: отменено", what)
	}

	if isNotFoundMessage(stderr) {
		name := strings.TrimPrefix(what, "show ")
		name = strings.TrimPrefix(name, "rm ")
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}

	msg := fmt.Sprintf("pass %s завершился с кодом %d", what, code)
	if hint := hintFor(stderr); hint != "" {
		msg += " (" + hint + ")"
	}
	if stderr != "" {
		msg += ": " + stderr
	}
	return errors.New(msg)
}

func isNotFoundMessage(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "not in the password store") ||
		strings.Contains(s, "no such file or directory") ||
		strings.Contains(s, "does not exist")
}

func hintFor(stderr string) string {
	s := strings.ToLower(stderr)
	switch {
	case strings.Contains(s, "decryption failed"), strings.Contains(s, "no secret key"):
		return "проверьте gpg-ключ и .gpg-id"
	case strings.Contains(s, "cancelled"), strings.Contains(s, "canceled"), strings.Contains(s, "cancel"):
		return "операция отменена в pinentry"
	case strings.Contains(s, "no public key"), strings.Contains(s, "unusable public key"):
		return "нет публичного ключа получателя"
	}
	return ""
}

// ParseSecret splits a decrypted payload into password, "Key: value" fields
// and free-form notes.
func ParseSecret(name, raw string) *Secret {
	sec := &Secret{Name: name, Raw: raw}

	body := strings.TrimRight(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	lines := strings.Split(body, "\n")
	sec.Password = lines[0]

	rest := lines[1:]
	for len(rest) > 0 {
		line := rest[0]
		key, value, ok := splitField(line)
		if !ok {
			break
		}
		sec.Fields = append(sec.Fields, Field{Key: key, Value: value})
		rest = rest[1:]
	}

	// Drop a single blank separator line between metadata and notes.
	if len(rest) > 0 && strings.TrimSpace(rest[0]) == "" {
		rest = rest[1:]
	}
	sec.Notes = strings.TrimRight(strings.Join(rest, "\n"), "\n")
	return sec
}

// splitField parses a "Key: value" line. Keys may not contain spaces at the
// start, which keeps URLs such as "https://example.com" from being treated as
// metadata.
func splitField(line string) (key, value string, ok bool) {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	// A URL scheme looks like "https:" and is not a metadata key.
	if strings.Contains(line[:idx], "//") {
		return "", "", false
	}
	return key, strings.TrimSpace(line[idx+1:]), true
}

// normalizeContent turns CRLF into LF and guarantees a trailing newline.
func normalizeContent(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.TrimRight(content, "\n")
	if content == "" {
		return ""
	}
	return content + "\n"
}

// ValidateName checks that name is a safe path inside the store.
func ValidateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("имя записи не может быть пустым")
	}
	if strings.HasSuffix(name, ".gpg") {
		name = strings.TrimSuffix(name, ".gpg")
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "~") {
		return errors.New("имя не должно начинаться с «/» или «~»")
	}
	if strings.ContainsAny(name, "\x00\n\r") {
		return errors.New("имя содержит недопустимые символы")
	}
	for _, part := range strings.Split(name, "/") {
		switch part {
		case "":
			return errors.New("имя содержит пустой сегмент пути")
		case ".", "..":
			return errors.New(`имя не должно содержать «.» или «..»`)
		}
		if strings.HasPrefix(part, ".") {
			return errors.New("сегменты имени не должны начинаться с точки")
		}
	}
	return nil
}
