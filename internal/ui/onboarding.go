package ui

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/beatlezhis/go-pass/internal/pass"
)

// ShowSetupWizard opens a standalone onboarding window when no password store
// or PGP key is configured yet. Once setup completes, onReady is called.
func ShowSetupWizard(fyneApp fyne.App, store *pass.Store, kr *pass.Keyring, onReady func()) {
	win := fyneApp.NewWindow("Go Pass — Настройка хранилища")
	win.Resize(fyne.NewSize(560, 470))
	win.CenterOnScreen()

	// --- Вкладка 1: Создание нового хранилища ---
	newDirEntry := widget.NewEntry()
	newDirEntry.SetText(store.Dir)

	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Например: Иван Иванов")

	emailEntry := widget.NewEntry()
	emailEntry.SetPlaceHolder("ivan@example.com")

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Придумайте надёжный мастер-пароль")

	passConfirmEntry := widget.NewPasswordEntry()
	passConfirmEntry.SetPlaceHolder("Повторите мастер-пароль")

	createErrLabel := widget.NewLabel("")
	createErrLabel.Wrapping = fyne.TextWrapWord

	var createBtn *widget.Button
	createBtn = widget.NewButtonWithIcon("Создать хранилище", theme.ConfirmIcon(), func() {
		dir := strings.TrimSpace(newDirEntry.Text)
		owner := strings.TrimSpace(nameEntry.Text)
		email := strings.TrimSpace(emailEntry.Text)
		pw := passEntry.Text

		switch {
		case dir == "":
			createErrLabel.SetText("Укажите папку для хранения паролей.")
			return
		case owner == "":
			createErrLabel.SetText("Укажите имя владельца ключа.")
			return
		case len(pw) < 6:
			createErrLabel.SetText("Мастер-пароль должен содержать минимум 6 символов.")
			return
		case pw != passConfirmEntry.Text:
			createErrLabel.SetText("Пароли не совпадают.")
			return
		}

		createBtn.Disable()
		createErrLabel.SetText("Генерация PGP-ключа…")

		go func() {
			meta, err := kr.GenerateAndSave(owner, email, pw)
			if err == nil {
				err = pass.InitStore(dir, meta.Fingerprint)
			}
			fyne.Do(func() {
				createBtn.Enable()
				if err != nil {
					createErrLabel.SetText("Ошибка: " + err.Error())
					return
				}
				store.Dir = dir
				store.Keyring = kr
				win.Close()
				onReady()
			})
		}()
	})
	createBtn.Importance = widget.HighImportance

	createForm := container.NewVBox(
		widget.NewLabel("Будет создан новый PGP-ключ и папка хранилища, совместимая со стандартным pass."),
		widget.NewForm(
			widget.NewFormItem("Папка хранилища", newDirEntry),
			widget.NewFormItem("Ваше имя", nameEntry),
			widget.NewFormItem("Email", emailEntry),
			widget.NewFormItem("Мастер-пароль", passEntry),
			widget.NewFormItem("Подтверждение", passConfirmEntry),
		),
		createErrLabel,
		layout.NewSpacer(),
		container.NewHBox(layout.NewSpacer(), createBtn),
	)

	// --- Вкладка 2: Открыть существующее хранилище ---
	existDirEntry := widget.NewEntry()
	existDirEntry.SetText(store.Dir)

	keyArmorEntry := widget.NewMultiLineEntry()
	keyArmorEntry.SetPlaceHolder("-----BEGIN PGP PRIVATE KEY BLOCK-----\n...")
	keyArmorEntry.SetMinRowsVisible(7)

	loadKeyFileBtn := widget.NewButtonWithIcon("Загрузить из файла (.asc)…", theme.FolderOpenIcon(), func() {
		dialog.ShowFileOpen(func(rc fyne.URIReadCloser, err error) {
			if err != nil || rc == nil {
				return
			}
			defer rc.Close()
			data, readErr := io.ReadAll(rc)
			if readErr == nil {
				keyArmorEntry.SetText(string(data))
			}
		}, win)
	})

	importErrLabel := widget.NewLabel("")
	importErrLabel.Wrapping = fyne.TextWrapWord

	importBtn := widget.NewButtonWithIcon("Открыть хранилище", theme.ConfirmIcon(), func() {
		dir := strings.TrimSpace(existDirEntry.Text)
		armor := strings.TrimSpace(keyArmorEntry.Text)

		if dir == "" {
			importErrLabel.SetText("Укажите путь к существующему хранилищу.")
			return
		}
		if _, err := os.Stat(filepath.Join(dir, ".gpg-id")); err != nil {
			importErrLabel.SetText("В выбранной папке не найден файл .gpg-id.")
			return
		}
		if armor == "" && !kr.HasPrivateKey() {
			importErrLabel.SetText("Вставьте приватный PGP-ключ (.asc) или загрузите его из файла.")
			return
		}
		if !kr.HasPrivateKey() {
			importErrLabel.SetText("Импортирован только публичный ключ. Нужен приватный PGP-ключ (.asc).")
			return
		}
		if armor != "" {
			if err := kr.ImportArmor(armor); err != nil {
				importErrLabel.SetText(err.Error())
				return
			}
		}
		store.Dir = dir
		store.Keyring = kr
		win.Close()
		onReady()
	})
	importBtn.Importance = widget.HighImportance

	importForm := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Папка хранилища", existDirEntry),
		),
		container.NewHBox(widget.NewLabel("Приватный PGP-ключ (.asc):"), layout.NewSpacer(), loadKeyFileBtn),
		keyArmorEntry,
		importErrLabel,
		layout.NewSpacer(),
		container.NewHBox(layout.NewSpacer(), importBtn),
	)

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Новое хранилище", theme.ContentAddIcon(), container.NewPadded(createForm)),
		container.NewTabItemWithIcon("Открыть существующее", theme.FolderOpenIcon(), container.NewPadded(importForm)),
	)

	header := container.NewVBox(
		widget.NewLabelWithStyle("Добро пожаловать в Go Pass", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
	)

	win.SetContent(container.NewBorder(container.NewPadded(header), nil, nil, nil, tabs))
	win.Show()
}

// promptUnlockAndRetry shows a master-password dialog when store.Show returns
// pass.ErrLocked, unlocks the keyring in memory and retries opening name.
func (a *App) promptUnlockAndRetry(name string) {
	if a.store == nil || a.store.Keyring == nil {
		a.report(pass.ErrLocked)
		return
	}

	pwEntry := widget.NewPasswordEntry()
	pwEntry.SetPlaceHolder("Введите мастер-пароль ключа")

	errLabel := widget.NewLabel("")
	form := container.NewVBox(
		widget.NewLabel("Для расшифровки записей разблокируйте PGP-ключ:"),
		pwEntry,
		errLabel,
	)

	var d dialog.Dialog
	submit := func() {
		pw := pwEntry.Text
		if pw == "" {
			errLabel.SetText("Введите пароль")
			return
		}
		if err := a.store.Keyring.Unlock(pw); err != nil {
			errLabel.SetText("Неверный мастер-пароль")
			pwEntry.SetText("")
			return
		}
		if d != nil {
			d.Hide()
		}
		a.setStatus("Ключ разблокирован")
		a.showEntry(name)
	}

	pwEntry.OnSubmitted = func(string) { submit() }

	d = dialog.NewCustomConfirm(
		"Разблокировка хранилища",
		"Разблокировать",
		"Отмена",
		form,
		func(ok bool) {
			if ok {
				submit()
			} else {
				a.setStatus("Расшифровка отменена")
			}
		},
		a.win,
	)
	d.Resize(fyne.NewSize(420, 190))
	d.Show()
	a.win.Canvas().Focus(pwEntry)
}

// lockSession clears unlocked private keys and cached secrets from memory.
func (a *App) lockSession() {
	if a.store != nil && a.store.Keyring != nil {
		a.store.Keyring.Lock()
	}
	a.cacheReset()
	a.clearSelection()
	a.setStatus("Хранилище заблокировано")
}

func isLockedErr(err error) bool {
	return errors.Is(err, pass.ErrLocked)
}
