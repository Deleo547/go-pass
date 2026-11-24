// Package ui renders the desktop front-end of the password manager.
package ui

import (
	"context"
	"errors"
	"fmt"
	"image/color"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/beatlezhis/go-pass/internal/clipboard"
	"github.com/beatlezhis/go-pass/internal/pass"
)

// Options configures the application window.
type Options struct {
	// Store is the password store backend (required).
	Store *pass.Store
	// Clip copies secrets to the system clipboard (required).
	Clip *clipboard.Manager
	// AppID is the Fyne application id, e.g. "com.github.beatlezhis.gopass".
	AppID string
	// Sync runs store operations and UI updates inline instead of in
	// background goroutines. Tests use it to stay deterministic.
	Sync bool
	// Scale sets the UI density (1 = stock Fyne, 0.85 = compact default).
	Scale float32
}

// App holds the widgets and state of the main window.
type App struct {
	store *pass.Store
	clip  *clipboard.Manager
	app   fyne.App
	win   fyne.Window

	entries []pass.Entry             // all entries of the store
	visible []pass.Entry             // entries matching the current filter
	nodes   map[string]*treeNodeInfo // uid -> folder/entry node of the tree

	selected string       // name shown in the detail pane
	current  *pass.Secret // decrypted entry shown in the detail pane
	revealed bool         // password is displayed in clear text

	search      *widget.Entry
	tree        *widget.Tree
	listEmpty   *widget.Label
	title       *elidedText
	passLabel   *widget.Label
	details     *widget.Label
	revealBtn   *widget.Button
	copyBtn     *widget.Button
	editBtn     *widget.Button
	deleteBtn   *widget.Button
	toggleBtn   *widget.Button
	status      *widget.Label
	placeholder fyne.CanvasObject
	detail      fyne.CanvasObject
	card        fyne.CanvasObject

	synchronous bool

	mu    sync.Mutex
	cache map[string]*pass.Secret

	clearAfter  time.Duration
	wasFiltered bool

	// savedOpen keeps the expanded folders while a search is active.
	savedOpen []string
	// noPersist suppresses saving of the expanded state (during filtering).
	noPersist bool
}

// New builds the application UI on top of the given Fyne application.
// It does not start the event loop, which keeps the window testable.
func New(fyneApp fyne.App, opts Options) (*App, error) {
	if opts.Store == nil || opts.Clip == nil {
		return nil, errors.New("ui: store и clipboard обязательны")
	}
	if fyneApp == nil {
		return nil, errors.New("ui: fyne.App обязателен")
	}

	applyTheme(fyneApp, opts.Scale)
	fyneApp.SetIcon(appIcon())

	a := &App{
		store:       opts.Store,
		clip:        opts.Clip,
		app:         fyneApp,
		cache:       make(map[string]*pass.Secret),
		synchronous: opts.Sync,
		clearAfter:  opts.Clip.Timeout,
	}

	a.clip.OnClear = func() {
		a.uiDo(func() { a.setStatus("Буфер обмена очищен") })
	}

	a.win = fyneApp.NewWindow("Go Pass — менеджер паролей")
	a.win.Resize(a.restoredWindowSize())
	a.win.SetMaster()
	a.build()
	a.restoreOpenBranches()
	a.registerShortcuts()
	a.win.SetOnClosed(func() {
		a.saveWindowSize()
		a.clip.Stop()
	})
	a.reload()
	return a, nil
}

// Window returns the main window.
func (a *App) Window() fyne.Window {
	return a.win
}

// Run creates the window and blocks until it is closed.
func Run(opts Options) error {
	id := opts.AppID
	if id == "" {
		id = "com.github.beatlezhis.gopass"
	}
	fyneApp := app.NewWithID(id)

	if opts.Store != nil && opts.Store.Keyring != nil && !opts.Store.IsInitialized() {
		ShowSetupWizard(fyneApp, opts.Store, opts.Store.Keyring, func() {
			a, err := New(fyneApp, opts)
			if err != nil {
				dialog.ShowError(err, nil)
				return
			}
			a.Window().Show()
		})
		fyneApp.Run()
		return nil
	}

	a, err := New(fyneApp, opts)
	if err != nil {
		return err
	}
	a.Window().ShowAndRun()
	return nil
}

// themeSize reads a metric from the current theme.
func (a *App) themeSize(name fyne.ThemeSizeName) float32 {
	if th := a.app.Settings().Theme(); th != nil {
		return th.Size(name)
	}
	return theme.DefaultTheme().Size(name)
}

// uiDo runs fn on the UI goroutine. Everything that touches widgets from a
// background goroutine must go through it.
func (a *App) uiDo(fn func()) {
	if a.synchronous {
		fn()
		return
	}
	fyne.Do(fn)
}

// async runs fn in the background, or inline in synchronous (test) mode.
func (a *App) async(fn func()) {
	if a.synchronous {
		fn()
		return
	}
	go fn()
}

func appIDOr(id string) string {
	if id == "" {
		return "com.github.beatlezhis.gopass"
	}
	return id
}

// build assembles the widget tree.
func (a *App) build() {
	a.search = widget.NewEntry()
	a.search.SetPlaceHolder("Поиск: github, vpn, …")
	a.search.OnChanged = func(string) { a.applyFilter() }
	a.search.OnSubmitted = func(string) { a.selectFirst() }

	a.tree = widget.NewTree(
		func(uid widget.TreeNodeID) []widget.TreeNodeID {
			if n := a.nodes[uid]; n != nil {
				return n.children
			}
			return nil
		},
		func(uid widget.TreeNodeID) bool {
			n := a.nodes[uid]
			return n != nil && len(n.children) > 0
		},
		a.nodeCreate,
		a.nodeUpdate,
	)
	a.tree.HideSeparators = true
	a.tree.OnSelected = a.treeSelected
	a.tree.OnBranchOpened = func(string) { a.onBranchChanged() }
	a.tree.OnBranchClosed = func(string) { a.onBranchChanged() }

	a.listEmpty = widget.NewLabel("Хранилище пустое")
	a.listEmpty.Alignment = fyne.TextAlignCenter
	a.listEmpty.TextStyle = fyne.TextStyle{Italic: true}
	a.listEmpty.Hide()

	a.nodes = buildTreeNodes(nil)

	leftContent := container.NewBorder(a.search, nil, nil, nil,
		container.NewStack(a.tree, container.NewCenter(a.listEmpty)))
	sidebar := canvas.NewRectangle(colorSidebar)
	left := container.NewStack(sidebar,
		container.New(layout.NewCustomPaddedLayout(8, 6, 8, 8), leftContent))

	a.title = newElidedText()
	a.title.SetBold(true)
	a.title.SetTextSize(a.themeSize(theme.SizeNameSubHeadingText))

	a.passLabel = widget.NewLabel("")
	a.passLabel.TextStyle = fyne.TextStyle{Monospace: true}
	a.passLabel.Wrapping = fyne.TextWrapBreak
	a.passLabel.Truncation = fyne.TextTruncateOff

	a.revealBtn = widget.NewButtonWithIcon("Показать", theme.VisibilityIcon(), a.toggleReveal)
	a.revealBtn.Importance = widget.LowImportance
	a.revealBtn.Disable()

	a.copyBtn = widget.NewButtonWithIcon("Копировать пароль", theme.ContentCopyIcon(), a.copyPassword)
	a.copyBtn.Importance = widget.HighImportance
	a.copyBtn.Disable()

	a.editBtn = widget.NewButtonWithIcon("Редактировать", theme.DocumentCreateIcon(), a.showEditDialog)
	a.editBtn.Importance = widget.LowImportance
	a.editBtn.Disable()

	a.deleteBtn = widget.NewButtonWithIcon("Удалить", theme.DeleteIcon(), a.confirmDelete)
	a.deleteBtn.Importance = widget.DangerImportance
	a.deleteBtn.Disable()

	copyAllBtn := widget.NewButtonWithIcon("Копировать всё", theme.ContentCopyIcon(), a.copyAll)
	copyAllBtn.Importance = widget.LowImportance

	a.details = widget.NewLabel("")
	a.details.TextStyle = fyne.TextStyle{Monospace: true}
	a.details.Wrapping = fyne.TextWrapWord
	a.details.Truncation = fyne.TextTruncateOff

	passwordBox := container.NewVBox(
		sectionLabel("ПАРОЛЬ"),
		container.NewBorder(nil, nil, nil, container.NewHBox(a.revealBtn, copyAllBtn), a.passLabel),
		container.NewBorder(nil, nil, container.NewHBox(a.copyBtn, a.editBtn), a.deleteBtn),
		widget.NewSeparator(),
		sectionLabel("МЕТАДАННЫЕ И ЗАМЕТКИ"),
	)

	detailBody := container.NewBorder(
		container.NewVBox(a.title, passwordBox),
		nil, nil, nil,
		container.NewVScroll(a.details),
	)
	a.detail = detailBody

	placeholderLabel := widget.NewLabel("Выберите запись в дереве слева —\nпароль будет расшифрован через pass")
	placeholderLabel.Alignment = fyne.TextAlignCenter
	a.placeholder = container.NewCenter(placeholderLabel)

	// Карточка в стиле Obsidian: тёмная панель со скруглёнными углами.
	card := canvas.NewRectangle(colorPanel)
	card.CornerRadius = 8
	card.StrokeColor = colorBorder
	card.StrokeWidth = 1
	a.card = container.NewStack(card,
		container.New(layout.NewCustomPaddedLayout(12, 12, 14, 14),
			container.NewStack(a.placeholder, a.detail)))

	a.status = widget.NewLabel("Готово")
	a.status.Truncation = fyne.TextTruncateEllipsis

	backendMode := "pass"
	if a.store.Keyring != nil {
		backendMode = "embedded"
	}
	storeLabel := widget.NewLabel(fmt.Sprintf("[%s] %s", backendMode, abbreviateHome(a.store.Dir)))
	storeLabel.TextStyle = fyne.TextStyle{Italic: true}
	storeLabel.Alignment = fyne.TextAlignTrailing

	statusBar := container.NewBorder(nil, nil,
		container.NewHBox(widget.NewIcon(theme.InfoIcon())),
		storeLabel,
		a.status,
	)

	split := container.NewHSplit(left,
		container.New(layout.NewCustomPaddedLayout(6, 6, 6, 6), a.card))
	split.SetOffset(0.30)

	statusBg := canvas.NewRectangle(colorSidebar)
	status := container.NewStack(statusBg,
		container.New(layout.NewCustomPaddedLayout(2, 2, 8, 8), statusBar))

	a.win.SetContent(container.NewBorder(a.toolbar(), status, nil, nil, split))
	a.showDetail(false)
}

// toolbar builds the top toolbar.
// toolbar builds the top toolbar.
func (a *App) toolbar() fyne.CanvasObject {
	addBtn := widget.NewButtonWithIcon("Добавить", theme.ContentAddIcon(), a.showAddDialog)
	addBtn.Importance = widget.HighImportance

	refreshBtn := widget.NewButtonWithIcon("Обновить", theme.ViewRefreshIcon(), func() {
		a.cacheReset()
		a.reload()
	})

	a.toggleBtn = widget.NewButtonWithIcon("Развернуть", theme.MenuExpandIcon(), a.toggleAllBranches)
	a.toggleBtn.Importance = widget.LowImportance

	var right fyne.CanvasObject
	if a.store != nil && a.store.Keyring != nil {
		lockBtn := widget.NewButtonWithIcon("Заблокировать", theme.VisibilityOffIcon(), a.lockSession)
		lockBtn.Importance = widget.LowImportance
		right = lockBtn
	}

	bar := container.NewBorder(nil, nil,
		container.NewHBox(addBtn, refreshBtn, a.toggleBtn), right)
	bg := canvas.NewRectangle(colorSidebar)
	return container.NewVBox(
		container.NewStack(bg, container.New(layout.NewCustomPaddedLayout(6, 6, 8, 8), bar)),
		widget.NewSeparator(),
	)
}

// registerShortcuts wires Cmd/Ctrl+C and Cmd/Ctrl+N.
func (a *App) registerShortcuts() {
	ctrl := fyne.KeyModifierControl
	if isMac() {
		ctrl = fyne.KeyModifierSuper
	}
	add := &desktop.CustomShortcut{KeyName: fyne.KeyN, Modifier: ctrl}
	a.win.Canvas().AddShortcut(add, func(fyne.Shortcut) { a.showAddDialog() })

	copyShortcut := &desktop.CustomShortcut{KeyName: fyne.KeyC, Modifier: ctrl}
	a.win.Canvas().AddShortcut(copyShortcut, func(fyne.Shortcut) {
		focused := a.win.Canvas().Focused()
		if focused == nil || focused == a.tree {
			a.copyPassword()
		}
	})

	edit := &desktop.CustomShortcut{KeyName: fyne.KeyE, Modifier: ctrl}
	a.win.Canvas().AddShortcut(edit, func(fyne.Shortcut) { a.showEditDialog() })

	del := &desktop.CustomShortcut{KeyName: fyne.KeyBackspace, Modifier: ctrl}
	a.win.Canvas().AddShortcut(del, func(fyne.Shortcut) {
		// Только когда фокус в дереве: при открытом диалоге без фокуса
		// (прогресс, подтверждение) удалять ничего нельзя.
		if a.win.Canvas().Focused() == a.tree {
			a.confirmDelete()
		}
	})

	find := &desktop.CustomShortcut{KeyName: fyne.KeyF, Modifier: ctrl}
	a.win.Canvas().AddShortcut(find, func(fyne.Shortcut) { a.win.Canvas().Focus(a.search) })
}

// reload reads the store listing in the background.
func (a *App) reload() {
	a.setStatus("Чтение хранилища…")
	previous := a.selected
	a.async(func() {
		entries, err := a.store.List()
		a.uiDo(func() {
			if err != nil {
				a.report(err)
				return
			}
			a.setEntries(entries)
			if previous != "" {
				a.selectByName(previous)
			}
		})
	})
}

// setEntries replaces the entry list and reapplies the filter.
func (a *App) setEntries(entries []pass.Entry) {
	a.entries = entries
	a.applyFilter()
}

// applyFilter rebuilds the filtered entry list and the tree that displays it.
func (a *App) applyFilter() {
	q := strings.ToLower(strings.TrimSpace(a.search.Text))

	// Раскрытые папки запоминаем до перестройки дерева: в отфильтрованном
	// наборе нужных веток может не оказаться.
	if q != "" && !a.wasFiltered {
		a.savedOpen = a.collectOpenBranches()
	}

	a.visible = a.visible[:0]
	for _, e := range a.entries {
		if q == "" || strings.Contains(strings.ToLower(e.Name), q) {
			a.visible = append(a.visible, e)
		}
	}
	a.nodes = buildTreeNodes(a.visible)
	a.tree.Refresh()

	// Пока идёт поиск, раскрываем всё найденное; при сбросе поиска возвращаем
	// дерево к тому виду, который пользователь настроил сам.
	if q != "" {
		a.withoutPersist(func() { a.tree.OpenAllBranches() })
	} else if a.wasFiltered {
		a.withoutPersist(func() { a.tree.CloseAllBranches() })
		a.openBranches(a.savedOpen)
	}
	a.wasFiltered = q != ""

	if len(a.visible) == 0 {
		if q == "" {
			a.listEmpty.SetText("Хранилище пустое")
		} else {
			a.listEmpty.SetText("Ничего не найдено")
		}
		a.listEmpty.Show()
	} else {
		a.listEmpty.Hide()
	}

	a.refreshTreeToggle()
	a.updateCountStatus()
}

// updateCountStatus shows how many entries are in the store and in the filter.
func (a *App) updateCountStatus() {
	if strings.TrimSpace(a.search.Text) == "" {
		a.setStatus(fmt.Sprintf("Записей: %d", len(a.entries)))
		return
	}
	a.setStatus(fmt.Sprintf("Найдено: %d из %d", len(a.visible), len(a.entries)))
}

// selectFirst selects the first entry matching the current filter.
func (a *App) selectFirst() {
	if len(a.visible) == 0 {
		return
	}
	a.selectByName(a.visible[0].Name)
}

// selectByName opens the parent folders of name and selects the entry.
func (a *App) selectByName(name string) {
	if _, ok := a.nodes[name]; !ok {
		return
	}
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[:i], "/")
		if n := a.nodes[parent]; n != nil && len(n.children) > 0 {
			a.tree.OpenBranch(parent)
		}
	}
	// Снимаем выделение, чтобы Select гарантированно вызвал OnSelected: иначе
	// повторный выбор той же записи (например, после правки) ничего не обновит.
	a.tree.Unselect(name)
	a.tree.Select(name)
	a.tree.ScrollTo(name)
}

// prefOpenBranches is the preferences key that stores expanded folders.
const prefOpenBranches = "tree.openBranches"

// prefWindowSize stores the window size between runs.
const prefWindowSize = "window.size"

// defaultWindowSize is compact on purpose: the UI itself is dense and there is
// no reason to open a big empty window.
var defaultWindowSize = fyne.NewSize(920, 600)

// restoredWindowSize returns the size used in the previous run.
func (a *App) restoredWindowSize() fyne.Size {
	raw := a.app.Preferences().String(prefWindowSize)
	if raw != "" {
		var w, h float32
		if _, err := fmt.Sscanf(raw, "%gx%g", &w, &h); err == nil && w >= 400 && h >= 300 {
			return fyne.NewSize(w, h)
		}
	}
	return defaultWindowSize
}

// saveWindowSize remembers the current window size.
func (a *App) saveWindowSize() {
	size := a.win.Canvas().Size()
	if size.Width < 200 || size.Height < 200 {
		return // окно уже свернуто или скрыто
	}
	a.app.Preferences().SetString(prefWindowSize, fmt.Sprintf("%gx%g", size.Width, size.Height))
}

// onBranchChanged persists the expanded state after a user action.
func (a *App) onBranchChanged() {
	a.refreshTreeToggle()
	if a.noPersist {
		return
	}
	a.persistOpenBranches()
}

// withoutPersist runs fn without recording branch changes (used while filtering).
func (a *App) withoutPersist(fn func()) {
	previous := a.noPersist
	a.noPersist = true
	fn()
	a.noPersist = previous
}

// collectOpenBranches returns the uids of the currently expanded folders.
func (a *App) collectOpenBranches() []string {
	open := make([]string, 0, len(a.nodes))
	for uid, n := range a.nodes {
		if len(n.children) > 0 && a.tree.IsBranchOpen(uid) {
			open = append(open, uid)
		}
	}
	sort.Strings(open)
	return open
}

// persistOpenBranches stores the expanded folders in the app preferences, so
// the tree opens the same way next time.
func (a *App) persistOpenBranches() {
	a.app.Preferences().SetString(prefOpenBranches, strings.Join(a.collectOpenBranches(), "\n"))
}

// restoreOpenBranches expands the folders remembered from the previous run.
func (a *App) restoreOpenBranches() {
	a.openBranches(strings.Split(a.app.Preferences().String(prefOpenBranches), "\n"))
}

// openBranches expands the given folders without touching the stored state.
func (a *App) openBranches(uids []string) {
	a.withoutPersist(func() {
		for _, uid := range uids {
			if uid != "" {
				a.tree.OpenBranch(uid)
			}
		}
	})
}

// toggleAllBranches expands or collapses the whole tree from one button: it
// shows what the click will do, so there is no need for two separate buttons.
func (a *App) toggleAllBranches() {
	if a.allBranchesOpen() {
		a.collapseAllBranches()
	} else {
		a.expandAllBranches()
	}
	a.refreshTreeToggle()
}

// allBranchesOpen reports whether every folder with children is expanded.
func (a *App) allBranchesOpen() bool {
	branches := a.branchUIDs()
	if len(branches) == 0 {
		return false
	}
	for _, uid := range branches {
		if !a.tree.IsBranchOpen(uid) {
			return false
		}
	}
	return true
}

// branchUIDs lists every folder that has children in the current tree.
func (a *App) branchUIDs() []string {
	uids := make([]string, 0, len(a.nodes))
	for uid, n := range a.nodes {
		if len(n.children) > 0 {
			uids = append(uids, uid)
		}
	}
	return uids
}

// refreshTreeToggle keeps the single expand/collapse button in sync with the
// tree state.
func (a *App) refreshTreeToggle() {
	if a.toggleBtn == nil {
		return
	}
	if len(a.branchUIDs()) == 0 {
		a.toggleBtn.SetText("Развернуть")
		a.toggleBtn.SetIcon(theme.MenuExpandIcon())
		a.toggleBtn.Disable()
		return
	}
	a.toggleBtn.Enable()
	if a.allBranchesOpen() {
		a.toggleBtn.SetText("Свернуть")
		a.toggleBtn.SetIcon(theme.MenuDropDownIcon())
	} else {
		a.toggleBtn.SetText("Развернуть")
		a.toggleBtn.SetIcon(theme.MenuExpandIcon())
	}
	a.toggleBtn.Refresh()
}

// expandAllBranches opens every folder and remembers that.
func (a *App) expandAllBranches() {
	a.withoutPersist(func() { a.tree.OpenAllBranches() })
	a.persistOpenBranches()
}

// collapseAllBranches closes every folder and remembers that.
func (a *App) collapseAllBranches() {
	a.withoutPersist(func() { a.tree.CloseAllBranches() })
	a.persistOpenBranches()
}

// treeSelected handles a click on a tree row: folders expand, entries decrypt.
func (a *App) treeSelected(uid widget.TreeNodeID) {
	n := a.nodes[uid]
	if n == nil {
		return
	}
	if len(n.children) > 0 {
		// Папки только раскрываются: чтобы повторный клик снова переключал
		// ветку, выделение с папки снимается (Select не срабатывает дважды).
		a.tree.ToggleBranch(uid)
		a.tree.Unselect(uid)
		return
	}
	if n.secret {
		a.showEntry(uid)
	}
}

// treeNodeInfo is one node of the folder tree: either a folder (children) or a
// stored entry (secret).
type treeNodeInfo struct {
	children []string
	secret   bool
	// count is the number of stored entries in this subtree.
	count int
}

// buildTreeNodes turns a flat entry list into a folder tree. The empty uid is
// the invisible root, so its children are the top-level folders.
func buildTreeNodes(entries []pass.Entry) map[string]*treeNodeInfo {
	nodes := map[string]*treeNodeInfo{"": {}}

	for _, e := range entries {
		parts := strings.Split(e.Name, "/")
		parent := ""
		for i, part := range parts {
			_ = part
			uid := strings.Join(parts[:i+1], "/")
			if nodes[uid] == nil {
				nodes[uid] = &treeNodeInfo{}
				nodes[parent].children = append(nodes[parent].children, uid)
			}
			if i == len(parts)-1 {
				nodes[uid].secret = true
			}
			parent = uid
		}
	}

	var countSecrets func(uid string) int
	countSecrets = func(uid string) int {
		n := nodes[uid]
		if n == nil {
			return 0
		}
		c := 0
		if n.secret {
			c = 1
		}
		for _, child := range n.children {
			c += countSecrets(child)
		}
		n.count = c
		return c
	}
	countSecrets("")

	for _, n := range nodes {
		sort.Slice(n.children, func(i, j int) bool {
			bi := len(nodes[n.children[i]].children) > 0
			bj := len(nodes[n.children[j]].children) > 0
			if bi != bj {
				return bi // папки идут раньше записей
			}
			return n.children[i] < n.children[j]
		})
	}
	return nodes
}

// nodeCreate builds the template used for a tree row.
func (a *App) nodeCreate(branch bool) fyne.CanvasObject {
	icon := widget.NewIcon(theme.FolderIcon())
	if !branch {
		icon.SetResource(theme.DocumentIcon())
	}
	// Своя подпись без паддингов: иначе строка дерева вдвое выше текста.
	label := newElidedText()
	label.SetBold(branch)
	// Небольшой отступ между иконкой и подписью.
	gap := canvas.NewRectangle(color.Transparent)
	gap.SetMinSize(fyne.NewSize(4, 1))

	// Border даёт подписи всю оставшуюся ширину строки, поэтому длинные имена
	// обрезаются многоточием, а не сжимаются в ноль.
	return container.NewBorder(nil, nil, container.NewHBox(icon, gap), nil, label)
}

// nodeUpdate fills a tree row with the node's name and icon.
func (a *App) nodeUpdate(uid widget.TreeNodeID, branch bool, o fyne.CanvasObject) {
	icon, label := rowParts(o)
	if icon == nil || label == nil {
		return
	}

	name := baseName(uid)
	if branch {
		if n := a.nodes[uid]; n != nil {
			name = fmt.Sprintf("%s (%d)", name, n.count)
		}
	}
	label.SetText(name)
	label.SetBold(branch)
	if branch {
		icon.SetResource(theme.FolderIcon())
	} else {
		icon.SetResource(theme.DocumentIcon())
	}
}

// rowParts finds the icon and label of a tree row template, which nests them in
// a Border container.
func rowParts(o fyne.CanvasObject) (*widget.Icon, *elidedText) {
	var icon *widget.Icon
	var label *elidedText

	var walk func(fyne.CanvasObject)
	walk = func(obj fyne.CanvasObject) {
		switch v := obj.(type) {
		case *widget.Icon:
			icon = v
		case *elidedText:
			label = v
		case *fyne.Container:
			for _, child := range v.Objects {
				walk(child)
			}
		}
	}
	walk(o)
	return icon, label
}

// baseName returns the last path segment of a tree uid.
func baseName(uid string) string {
	if i := strings.LastIndexByte(uid, '/'); i >= 0 {
		return uid[i+1:]
	}
	return uid
}

// showEntry decrypts and displays the entry with the given name.
func (a *App) showEntry(name string) {
	if name == "" {
		return
	}
	a.selected = name
	a.current = nil
	a.revealed = false

	a.title.SetText(name)
	a.passLabel.SetText("")
	a.details.SetText("")
	a.revealBtn.SetText("Показать")
	a.revealBtn.Disable()
	a.copyBtn.Disable()
	a.editBtn.Disable()
	a.deleteBtn.Disable()
	a.showDetail(true)
	a.setStatus("Расшифровка " + name + "…")

	a.async(func() {
		secret, err := a.secret(name)
		a.uiDo(func() {
			if a.selected != name {
				return // a newer selection won the race
			}
			if err != nil {
				a.current = nil
				a.passLabel.SetText("—")
				a.details.SetText("")
				if isLockedErr(err) {
					a.setStatus("Требуется мастер-пароль для " + name)
					a.promptUnlockAndRetry(name)
					return
				}
				a.setStatus("Ошибка расшифровки " + name)
				a.report(err)
				return
			}
			a.render(secret)
		})
	})
}

// render fills the detail pane with a decrypted secret.
func (a *App) render(secret *pass.Secret) {
	a.current = secret
	a.revealed = false
	a.revealBtn.SetText("Показать")
	a.passLabel.SetText(maskPassword(secret.Password))
	a.details.SetText(descriptionText(secret))
	a.revealBtn.Enable()
	a.copyBtn.Enable()
	a.editBtn.Enable()
	a.deleteBtn.Enable()
	a.showDetail(true)
	a.setStatus(fmt.Sprintf("%s: пароль из %d символов", secret.Name, len([]rune(secret.Password))))
}

// maskPassword hides every character of the password.
func maskPassword(pwd string) string {
	if pwd == "" {
		return "—"
	}
	return strings.Repeat("•", len([]rune(pwd)))
}

// descriptionText renders metadata and notes for the read-only area.
func descriptionText(s *pass.Secret) string {
	var b strings.Builder
	for _, f := range s.Fields {
		fmt.Fprintf(&b, "%s: %s\n", f.Key, f.Value)
	}
	if s.Notes != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(s.Notes)
	}
	if b.Len() == 0 {
		return "—"
	}
	return strings.TrimRight(b.String(), "\n")
}

// secret returns the decrypted entry, using an in-memory cache.
func (a *App) secret(name string) (*pass.Secret, error) {
	a.mu.Lock()
	if s, ok := a.cache[name]; ok {
		a.mu.Unlock()
		return s, nil
	}
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), pass.DefaultTimeout)
	defer cancel()

	s, err := a.store.Show(ctx, name)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	a.cache[name] = s
	a.mu.Unlock()
	return s, nil
}

// cacheDelete drops the decrypted copy of one entry, e.g. after editing it.
func (a *App) cacheDelete(name string) {
	a.mu.Lock()
	delete(a.cache, name)
	a.mu.Unlock()
}

func (a *App) cacheReset() {
	a.mu.Lock()
	a.cache = make(map[string]*pass.Secret)
	a.mu.Unlock()
}

// toggleReveal switches the password between masked and clear text.
func (a *App) toggleReveal() {
	if a.current == nil {
		return
	}
	a.revealed = !a.revealed
	if a.revealed {
		a.passLabel.SetText(a.current.Password)
		a.revealBtn.SetText("Скрыть")
	} else {
		a.passLabel.SetText(maskPassword(a.current.Password))
		a.revealBtn.SetText("Показать")
	}
}

// copyPassword copies only the first line of the entry.
func (a *App) copyPassword() {
	if a.current == nil || a.current.Name != a.selected {
		a.setStatus("Сначала выберите запись")
		return
	}
	a.copyToClipboard(a.current.Password, "Пароль")
}

// copyAll copies the whole decrypted entry.
func (a *App) copyAll() {
	if a.current == nil || a.current.Name != a.selected {
		a.setStatus("Сначала выберите запись")
		return
	}
	a.copyToClipboard(a.current.Raw, "Вся запись")
}

func (a *App) copyToClipboard(text, what string) {
	if err := a.clip.Copy(text); err != nil {
		a.report(err)
		return
	}
	if a.clearAfter > 0 {
		a.setStatus(fmt.Sprintf("%s в буфере обмена, очистка через %s", what, humanDuration(a.clearAfter)))
		return
	}
	a.setStatus(what + " в буфере обмена")
}

// addFormState keeps what the user typed, so a validation error does not throw
// the form away.
type addFormState struct {
	name     string
	password string
	notes    string
}

// editFormState keeps what the user typed, so a validation error does not throw
// the edit form away.
type editFormState struct {
	password string
	extra    string
}

// showEditDialog opens the editor for the selected entry.
func (a *App) showEditDialog() {
	if a.current == nil || a.current.Name != a.selected {
		a.setStatus("Сначала выберите запись")
		return
	}
	a.showEditForm(a.current.Name, editFormState{
		password: a.current.Password,
		extra:    a.current.Extra(),
	})
}

// showEditForm renders the editor, optionally prefilled.
func (a *App) showEditForm(name string, state editFormState) {
	pwdEntry := widget.NewPasswordEntry()
	pwdEntry.TextStyle = fyne.TextStyle{Monospace: true}
	pwdEntry.SetText(state.password)

	extraEntry := widget.NewMultiLineEntry()
	extraEntry.TextStyle = fyne.TextStyle{Monospace: true}
	extraEntry.SetPlaceHolder("login: user@example.com\nurl: https://example.com\n\nзаметки")
	extraEntry.SetMinRowsVisible(6)
	extraEntry.SetText(state.extra)

	nameLabel := widget.NewLabelWithStyle(name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	hint := widget.NewLabel("Первая строка — пароль, остальное — метаданные и заметки.")
	hint.Wrapping = fyne.TextWrapWord
	hint.TextStyle = fyne.TextStyle{Italic: true}

	form := container.NewVBox(
		widget.NewLabel("Запись"),
		nameLabel,
		widget.NewLabel("Пароль"),
		pwdEntry,
		widget.NewLabel("Дополнительно"),
		extraEntry,
		hint,
	)

	d := dialog.NewCustomConfirm("Редактирование записи", "Сохранить", "Отмена", form, func(ok bool) {
		if !ok {
			return
		}
		if err := a.applyEdit(name, pwdEntry.Text, extraEntry.Text); err != nil {
			a.setStatus(err.Error())
			dialog.ShowError(err, a.win)
			// Возвращаем форму с введёнными данными, чтобы не терять правки.
			a.showEditForm(name, editFormState{password: pwdEntry.Text, extra: extraEntry.Text})
		}
	}, a.win)
	d.Resize(fyne.NewSize(580, 500))
	d.Show()
	a.win.Canvas().Focus(pwdEntry)
}

// applyEdit overwrites an existing entry with new content. `pass insert
// --force` keeps recipients, git commit and hooks intact.
func (a *App) applyEdit(name, password, extra string) error {
	if name == "" {
		return errors.New("запись не выбрана")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("пароль не может быть пустым")
	}

	content := password
	extra = strings.TrimRight(strings.ReplaceAll(extra, "\r\n", "\n"), "\n")
	if strings.TrimSpace(extra) != "" {
		content += "\n" + extra
	}

	// Старое расшифрованное значение больше не актуально.
	a.cacheDelete(name)
	a.saveEntry(name, content, true)
	return nil
}

// confirmDelete asks for confirmation before removing the selected entry.
func (a *App) confirmDelete() {
	if a.selected == "" {
		a.setStatus("Сначала выберите запись")
		return
	}
	name := a.selected

	message := widget.NewLabel(fmt.Sprintf(
		"Запись «%s» будет удалена из хранилища.\nВернуть её из приложения нельзя.", name))
	message.Wrapping = fyne.TextWrapWord

	d := dialog.NewCustomConfirm("Удалить запись?", "Удалить", "Отмена", message, func(yes bool) {
		if yes {
			a.deleteEntry(name)
		}
	}, a.win)
	d.SetConfirmImportance(widget.DangerImportance)
	d.Resize(fyne.NewSize(460, 200))
	d.Show()
}

// deleteEntry removes the entry via `pass rm --force`, clears its cached
// secret, resets the detail pane and reloads the tree.
func (a *App) deleteEntry(name string) {
	a.setStatus("Удаление " + name + "…")

	a.async(func() {
		ctx, cancel := context.WithTimeout(context.Background(), pass.DefaultTimeout)
		defer cancel()
		err := a.store.Delete(ctx, name)

		a.uiDo(func() {
			if err != nil {
				a.report(err)
				return
			}
			a.cacheDelete(name)
			if a.selected == name {
				a.clearSelection()
			}
			a.reloadAfterDelete(name)
		})
	})
}

func (a *App) reloadAfterDelete(deletedName string) {
	a.async(func() {
		entries, err := a.store.List()
		a.uiDo(func() {
			if err != nil {
				a.report(err)
				return
			}
			a.setEntries(entries)
			a.pruneStaleBranches(deletedName)
			a.setStatus("Запись «" + deletedName + "» удалена")
		})
	})
}

// pruneStaleBranches closes tree branch IDs that no longer exist in a.nodes
// and updates persisted preferences so dead folder IDs are not kept.
func (a *App) pruneStaleBranches(deletedName string) {
	parts := strings.Split(deletedName, "/")
	a.withoutPersist(func() {
		for i := 1; i < len(parts); i++ {
			uid := strings.Join(parts[:i], "/")
			if n := a.nodes[uid]; n == nil || len(n.children) == 0 {
				a.tree.CloseBranch(uid)
			}
		}
	})
	// Убираем удалённые ветки из запомненных: иначе после сброса поиска
	// дерево попробует их раскрыть.
	kept := a.savedOpen[:0]
	for _, uid := range a.savedOpen {
		if n := a.nodes[uid]; n != nil && len(n.children) > 0 {
			kept = append(kept, uid)
		}
	}
	a.savedOpen = kept

	if !a.wasFiltered {
		a.persistOpenBranches()
	}
}

// clearSelection resets the detail pane back to the empty placeholder state.
func (a *App) clearSelection() {
	if a.selected != "" {
		a.tree.Unselect(a.selected)
	}
	a.selected = ""
	a.current = nil
	a.revealed = false
	a.title.SetText("")
	a.passLabel.SetText("")
	a.details.SetText("")
	a.revealBtn.Disable()
	a.copyBtn.Disable()
	a.editBtn.Disable()
	a.deleteBtn.Disable()
	a.showDetail(false)
}

// showAddDialog asks for a name and content, then stores the entry.
func (a *App) showAddDialog() {
	a.showAddForm(addFormState{})
}

// showAddForm renders the "new entry" dialog, optionally prefilled.
func (a *App) showAddForm(state addFormState) {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("например: personal/mail")
	nameEntry.SetText(state.name)
	nameEntry.Validator = func(s string) error {
		if strings.TrimSpace(s) == "" {
			return nil // не ругаемся на пустое поле до сохранения
		}
		return pass.ValidateName(strings.TrimSuffix(strings.TrimSpace(s), ".gpg"))
	}

	dirs := a.existingDirs()
	namePart := container.NewVBox(widget.NewLabel("Имя записи"), nameEntry)
	if len(dirs) > 0 {
		dirSelect := widget.NewSelect(dirs, func(v string) {
			if v != "" {
				nameEntry.SetText(v + "/")
			}
		})
		dirSelect.PlaceHolder = "папка (необязательно)"
		namePart = container.NewVBox(
			widget.NewLabel("Имя записи"),
			nameEntry,
			widget.NewLabel("Существующие папки"),
			dirSelect,
		)
	}

	pwdEntry := widget.NewPasswordEntry()
	pwdEntry.TextStyle = fyne.TextStyle{Monospace: true}
	pwdEntry.SetPlaceHolder("пароль (первая строка записи)")
	pwdEntry.SetText(state.password)

	notesEntry := widget.NewMultiLineEntry()
	notesEntry.SetPlaceHolder("login: user@example.com\nurl: https://example.com\n\nлюбые заметки")
	notesEntry.SetMinRowsVisible(5)
	notesEntry.TextStyle = fyne.TextStyle{Monospace: true}
	notesEntry.SetText(state.notes)

	genBtn := widget.NewButtonWithIcon("Сгенерировать", theme.ContentRedoIcon(), func() {
		pwd, err := GeneratePassword(20)
		if err != nil {
			a.report(err)
			return
		}
		pwdEntry.Password = false // показать, чтобы пароль можно было проверить
		pwdEntry.SetText(pwd)
		pwdEntry.Refresh()
		a.setStatus("Сгенерирован пароль из 20 символов — нажмите «Сохранить»")
	})

	hint := widget.NewLabel("Пароль попадёт в первую строку, остальное — в метаданные записи.")
	hint.Wrapping = fyne.TextWrapWord
	hint.TextStyle = fyne.TextStyle{Italic: true}

	form := container.NewVBox(
		namePart,
		widget.NewLabel("Пароль"),
		container.NewBorder(nil, nil, nil, genBtn, pwdEntry),
		widget.NewLabel("Дополнительно"),
		notesEntry,
		hint,
	)

	// Keep the form open (by reopening it prefilled) when validation fails.
	reopen := func(err error) {
		a.setStatus(err.Error())
		a.showAddForm(addFormState{
			name:     nameEntry.Text,
			password: pwdEntry.Text,
			notes:    notesEntry.Text,
		})
	}

	d := dialog.NewCustomConfirm("Новая запись", "Сохранить", "Отмена", form, func(ok bool) {
		if !ok {
			return
		}
		name := strings.TrimSuffix(strings.TrimSpace(nameEntry.Text), ".gpg")
		if err := pass.ValidateName(name); err != nil {
			reopen(err)
			return
		}
		if pwdEntry.Text == "" {
			reopen(errors.New("пароль не может быть пустым"))
			return
		}

		content := pwdEntry.Text
		if extra := strings.TrimSpace(notesEntry.Text); extra != "" {
			content += "\n" + extra
		}

		if a.entryExists(name) {
			dialog.ShowConfirm("Перезаписать запись?",
				fmt.Sprintf("Запись «%s» уже есть в хранилище. Заменить её содержимое?", name),
				func(yes bool) {
					if yes {
						a.save(name, content)
					}
				}, a.win)
			return
		}
		a.save(name, content)
	}, a.win)
	d.Resize(fyne.NewSize(580, 520))
	d.Show()
	a.win.Canvas().Focus(nameEntry)
}

// existingDirs returns the distinct top-level directories of the store, used as
// quick suggestions in the "new entry" dialog.
func (a *App) existingDirs() []string {
	seen := make(map[string]struct{})
	var dirs []string
	for _, e := range a.entries {
		if i := strings.IndexByte(e.Name, '/'); i > 0 {
			d := e.Name[:i]
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				dirs = append(dirs, d)
			}
		}
	}
	sort.Strings(dirs)
	return dirs
}

// entryExists reports whether name is already present in the store listing.
func (a *App) entryExists(name string) bool {
	for _, e := range a.entries {
		if e.Name == name {
			return true
		}
	}
	return false
}

// save stores the entry in the background and refreshes the list afterwards.
// The search filter is reset so the new entry is visible.
func (a *App) save(name, content string) {
	a.saveEntry(name, content, false)
}

// saveEntry writes content to the store. keepFilter keeps the search box as is,
// which is what editing an existing entry wants.
func (a *App) saveEntry(name, content string, keepFilter bool) {
	progress := dialog.NewCustomWithoutButtons("Сохранение",
		container.NewVBox(
			widget.NewProgressBarInfinite(),
			widget.NewLabel("Шифрование через gpg. Если появится запрос парольной фразы — введите её."),
		), a.win)
	progress.Show()
	a.setStatus("Сохранение " + name + "…")

	a.async(func() {
		ctx, cancel := context.WithTimeout(context.Background(), pass.DefaultTimeout)
		defer cancel()
		err := a.store.Insert(ctx, name, content)

		a.uiDo(func() {
			progress.Hide()
			if err != nil {
				a.report(err)
				return
			}
			a.setStatus("Запись «" + name + "» сохранена")
			a.refreshAndSelect(name, keepFilter)
		})
	})
}

// refreshAndSelect reloads the listing and selects the given entry.
func (a *App) refreshAndSelect(name string, keepFilter bool) {
	a.async(func() {
		entries, err := a.store.List()
		a.uiDo(func() {
			if err != nil {
				a.report(err)
				return
			}
			if !keepFilter {
				a.search.SetText("")
			}
			a.setEntries(entries)
			a.selectByName(name)
			a.setStatus(fmt.Sprintf("Записей: %d", len(entries)))
		})
	})
}

func (a *App) showDetail(visible bool) {
	if visible {
		a.placeholder.Hide()
		a.detail.Show()
		return
	}
	a.detail.Hide()
	a.placeholder.Show()
}

func (a *App) setStatus(msg string) {
	a.status.SetText(msg)
}

// report shows an error both in the status bar and in a dialog.
func (a *App) report(err error) {
	msg := err.Error()
	a.setStatus(msg)
	dialog.ShowError(errors.New(msg), a.win)
}

// sectionLabel renders a small muted heading, like the panel titles in Obsidian.
func sectionLabel(text string) fyne.CanvasObject {
	label := canvas.NewText(text, colorMuted)
	label.TextSize = theme.CaptionTextSize()
	label.TextStyle = fyne.TextStyle{Bold: true}
	return label
}

// abbreviateHome shortens a path below the user's home directory to "~/...".
func abbreviateHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !strings.HasPrefix(path, home) {
		return path
	}
	return "~" + strings.TrimPrefix(path, home)
}

func humanDuration(d time.Duration) string {
	if d%time.Second == 0 {
		return fmt.Sprintf("%d с", int(d.Seconds()))
	}
	return d.String()
}
