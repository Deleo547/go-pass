// Command go-pass is a small desktop password manager for the standard unix
// password store (pass).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/beatlezhis/go-pass/internal/clipboard"
	"github.com/beatlezhis/go-pass/internal/pass"
	"github.com/beatlezhis/go-pass/internal/ui"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	storeDir := flag.String("store", "", "путь к хранилищу (по умолчанию $PASSWORD_STORE_DIR или ~/.password-store)")
	clearAfter := flag.Duration("clear-after", clipboard.DefaultTimeout, "через сколько очищать буфер обмена (0 — не очищать)")
	list := flag.Bool("list", false, "напечатать имена записей и выйти")
	show := flag.String("show", "", "напечатать пароль записи и выйти")
	copyName := flag.String("copy", "", "скопировать пароль записи в буфер обмена и выйти")
	appID := flag.String("app-id", "com.github.beatlezhis.gopass", "идентификатор приложения")
	uiScale := flag.Float64("ui-scale", float64(ui.DefaultUIScale), "плотность интерфейса: 1 — как в Fyne, меньше — компактнее")
	versionFlag := flag.Bool("version", false, "показать версию и выйти")
	deleteName := flag.String("delete", "", "удалить запись и выйти")
	backendFlag := flag.String("backend", "auto", "режим работы: auto (по умолчанию), cli (системный pass) или embedded (встроенный OpenPGP)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Go Pass %s — графический менеджер паролей для pass\n\n", version)
		fmt.Fprintf(os.Stderr, "Использование:\n  go-pass [флаги]\n\nФлаги:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionFlag {
		fmt.Println("go-pass", version)
		return
	}
	if *storeDir != "" {
		if err := os.Setenv("PASSWORD_STORE_DIR", *storeDir); err != nil {
			fail(fmt.Errorf("не удалось задать PASSWORD_STORE_DIR: %w", err))
		}
	}

	kr, err := pass.OpenKeyring("")
	if err != nil {
		fail(err)
	}
	if pw := os.Getenv("GOPASS_PASSPHRASE"); pw != "" && kr.HasPrivateKey() {
		if unlockErr := kr.Unlock(pw); unlockErr != nil {
			fail(unlockErr)
		}
	}

	store, err := pass.NewAuto(kr, pass.BackendMode(*backendFlag))
	if err != nil {
		fail(err)
	}

	switch {
	case *list:
		entries, err := store.List()
		if err != nil {
			fail(err)
		}
		for _, e := range entries {
			fmt.Println(e.Name)
		}
		return
	case *show != "":
		ctx, cancel := context.WithTimeout(context.Background(), pass.DefaultTimeout)
		defer cancel()
		secret, err := store.Show(ctx, *show)
		if err != nil {
			fail(err)
		}
		fmt.Print(secret.Raw)
		return
	case *copyName != "":
		ctx, cancel := context.WithTimeout(context.Background(), pass.DefaultTimeout)
		defer cancel()
		secret, err := store.Show(ctx, *copyName)
		if err != nil {
			fail(err)
		}
		clip, err := clipboard.New(*clearAfter)
		if err != nil {
			fail(err)
		}
		cleared := make(chan struct{})
		clip.OnClear = func() { close(cleared) }

		if err := clip.Copy(secret.Password); err != nil {
			fail(err)
		}
		if *clearAfter > 0 {
			fmt.Fprintf(os.Stderr, "Пароль из %s в буфере обмена, очистка через %s\n", *copyName, *clearAfter)
			select {
			case <-cleared:
				fmt.Fprintln(os.Stderr, "Буфер обмена очищен")
			case <-time.After(*clearAfter + 15*time.Second):
				fmt.Fprintln(os.Stderr, "Не удалось очистить буфер обмена")
			}
		}
		clip.Stop()
		return
	case *deleteName != "":
		ctx, cancel := context.WithTimeout(context.Background(), pass.DefaultTimeout)
		defer cancel()
		if err := store.Delete(ctx, *deleteName); err != nil {
			fail(err)
		}
		fmt.Printf("Запись %s удалена\n", *deleteName)
		return
	}

	clip, err := clipboard.New(*clearAfter)
	if err != nil {
		// Просмотр и добавление работают и без буфера обмена: кнопки
		// копирования будут показывать ошибку.
		fmt.Fprintln(os.Stderr, "go-pass: буфер обмена недоступен:", err)
		clip = clipboard.NewUnavailable(err)
	}

	if err := ui.Run(ui.Options{Store: store, Clip: clip, AppID: *appID, Scale: float32(*uiScale)}); err != nil {
		failGUI(err)
	}
}

// fail reports a CLI-mode error and exits.
func fail(err error) {
	fmt.Fprintln(os.Stderr, "go-pass:", err)
	os.Exit(1)
}

// failGUI reports an error that happens before the window exists. A compiled
// application bundle has no console, so on macOS a native alert is shown too.
func failGUI(err error) {
	fmt.Fprintln(os.Stderr, "go-pass:", err)
	notifyNative(err)
	os.Exit(1)
}

func notifyNative(err error) {
	if runtime.GOOS != "darwin" {
		return
	}
	msg := strings.NewReplacer(`"`, `'`, "\n", " ").Replace(err.Error())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	script := fmt.Sprintf(`display alert "Go Pass" message %q as critical`, msg)
	_ = exec.CommandContext(ctx, "osascript", "-e", script).Run()
}
