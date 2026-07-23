package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const banner = `
██████╗  █████╗ ████████╗███████╗██╗    ██╗███████╗███████╗██████╗ ██████╗
██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗██╔══██╗
██████╔╝███████║   ██║   ███████╗██║ █╗ ██║█████╗  █████╗  ██████╔╝██████╔╝
██╔══██╗██╔══██║   ██║   ╚════██║██║███╗██║██╔══╝  ██╔══╝  ██╔═══╝ ██╔══██╗
██║  ██║██║  ██║   ██║   ███████║╚███╔███╔╝███████╗███████╗██║     ██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝`

var (
	gradient = []string{"#FF5F87", "#F45FA0", "#E060B8", "#C468D0", "#A275E5", "#7A83F5"}

	styleDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleTag     = lipgloss.NewStyle().Foreground(lipgloss.Color("#7A83F5")).Bold(true)
	styleTitle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F87")).Bold(true)
	styleHigh    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleMed     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleInfo    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	styleOK      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleCursor  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F87")).Bold(true)
	styleItemSel = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Bold(true)
	styleWarnBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("214")).Padding(0, 2).
			Foreground(lipgloss.Color("214"))
)

func renderBanner() string {
	lines := strings.Split(strings.Trim(banner, "\n"), "\n")
	var b strings.Builder
	for i, l := range lines {
		c := gradient[i%len(gradient)]
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Render(l))
		b.WriteString("\n")
	}
	return b.String()
}

// ------------------------------ model ----------------------------------------

type state int

const (
	stMenu state = iota
	stBusy
	stResults
	stConfirm
	stPick
)

type menuItem struct {
	label string
	run   func(*model) tea.Cmd
}

type progressMsg string
type findingMsg Finding
type doneMsg struct{ lines []string }
type failMsg struct{ err error }

type confirmStep struct {
	warning string // shown above the input
	phrase  string // exact text the user must type
}

type model struct {
	env    *Env
	st     state
	width  int
	height int

	menu    []menuItem
	cursor  int
	status  string
	spin    spinner.Model
	busyLog []string
	events  chan tea.Msg

	vp        viewport.Model
	vpReady   bool
	resultTxt string

	confirms  []confirmStep
	confirmAt int
	input     textinput.Model
	onOK      func(*model) tea.Cmd

	pickItems []string
	pickAt    int
	onPick    func(*model, string) tea.Cmd
	pickTitle string

	findings []Finding
}

func newModel(e *Env) *model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F87"))
	ti := textinput.New()
	ti.Prompt = "> "
	m := &model{env: e, spin: sp, input: ti, events: make(chan tea.Msg, 256)}
	m.menu = []menuItem{
		{"Scan (read-only — recommended first step)", (*model).doScan},
		{"Update malware signatures (rfxn.hdb + patterns)", (*model).doUpdateSigs},
		{"Quarantine findings from a report", (*model).doQuarantinePick},
		{"Restore a quarantine batch", (*model).doRestorePick},
		{"Clean core (replace only failing files)", (*model).doCleanCore},
		{"Generate premium baselines (on a CLEAN site)", (*model).doBaseline},
		{"Verify against baselines", (*model).doBaselineVerify},
		{"Rotate wp-config salts", (*model).doSalts},
		{"Quit", func(*model) tea.Cmd { return tea.Quit }},
	}
	return m
}

func (m *model) Init() tea.Cmd { return m.spin.Tick }

func (m *model) listen() tea.Cmd {
	return func() tea.Msg { return <-m.events }
}

// ------------------------------ update ---------------------------------------

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		vh := m.height - 12
		if vh < 5 {
			vh = 5
		}
		if !m.vpReady {
			m.vp = viewport.New(m.width-2, vh)
			m.vpReady = true
		} else {
			m.vp.Width, m.vp.Height = m.width-2, vh
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case progressMsg:
		m.busyLog = append(m.busyLog, string(msg))
		if len(m.busyLog) > 8 {
			m.busyLog = m.busyLog[len(m.busyLog)-8:]
		}
		return m, m.listen()

	case findingMsg:
		m.findings = append(m.findings, Finding(msg))
		return m, m.listen()

	case doneMsg:
		m.st = stResults
		m.resultTxt = m.renderResults(msg.lines)
		if m.vpReady {
			m.vp.SetContent(m.resultTxt)
			m.vp.GotoTop()
		}
		return m, nil

	case failMsg:
		m.st = stMenu
		m.status = styleHigh.Render("✗ " + msg.err.Error())
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	if m.st == stConfirm {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.st {
	case stMenu:
		switch k.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.menu)-1 {
				m.cursor++
			}
		case "enter":
			m.status = ""
			return m, m.menu[m.cursor].run(m)
		}
	case stBusy:
		if k.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case stResults:
		switch k.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q", "esc", "enter":
			m.st = stMenu
			return m, nil
		default:
			var cmd tea.Cmd
			m.vp, cmd = m.vp.Update(k)
			return m, cmd
		}
	case stConfirm:
		switch k.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.st = stMenu
			m.status = styleDim.Render("aborted — no changes made")
			return m, nil
		case "enter":
			if m.input.Value() == m.confirms[m.confirmAt].phrase {
				m.confirmAt++
				m.input.SetValue("")
				if m.confirmAt >= len(m.confirms) {
					return m, m.onOK(m)
				}
			} else {
				m.input.SetValue("")
				m.status = styleHigh.Render("phrase did not match — type it exactly, or Esc to abort")
			}
			return m, nil
		default:
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(k)
			return m, cmd
		}
	case stPick:
		switch k.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc", "q":
			m.st = stMenu
			return m, nil
		case "up", "k":
			if m.pickAt > 0 {
				m.pickAt--
			}
		case "down", "j":
			if m.pickAt < len(m.pickItems)-1 {
				m.pickAt++
			}
		case "enter":
			if len(m.pickItems) > 0 {
				return m, m.onPick(m, m.pickItems[m.pickAt])
			}
		}
	}
	return m, nil
}

// ------------------------------ actions --------------------------------------

func (m *model) busy(label string) {
	m.st = stBusy
	m.busyLog = []string{label}
	m.findings = nil
}

func (m *model) doScan() tea.Cmd {
	m.busy("Starting scan…")
	env := m.env
	ev := m.events
	go func() {
		for _, l := range env.UpdateSignatures() {
			ev <- progressMsg(l)
		}
		sigs, err := env.LoadSignatures()
		if err != nil {
			ev <- failMsg{err}
			return
		}
		sc := NewScanner(env, sigs,
			func(p string) { ev <- progressMsg(p) },
			func(f Finding) { ev <- findingMsg(f) })
		sc.RunAll()
		ev <- doneMsg{[]string{"Full report: " + env.ReportPath}}
	}()
	return m.listen()
}

func (m *model) doUpdateSigs() tea.Cmd {
	m.busy("Updating signatures…")
	env, ev := m.env, m.events
	go func() { ev <- doneMsg{env.UpdateSignatures()} }()
	return m.listen()
}

func backupConfirm(extra confirmStep) []confirmStep {
	return []confirmStep{
		{
			warning: "This action will MODIFY your site. RatSweepr does not create\n" +
				"backups. Before continuing, make a FULL backup yourself:\n" +
				"  files:     tar -czf ~/site-backup.tgz .\n" +
				"  database:  wp db export ~/db-backup.sql",
			phrase: "I HAVE A BACKUP",
		},
		extra,
	}
}

func (m *model) doQuarantinePick() tea.Cmd {
	reports, _ := filepath.Glob(filepath.Join(m.env.WPRoot, "ratsweepr-*.report"))
	sort.Sort(sort.Reverse(sort.StringSlice(reports)))
	if len(reports) == 0 {
		m.status = styleMed.Render("no reports found — run a scan first")
		return nil
	}
	m.st = stPick
	m.pickTitle = "Pick a report to quarantine from"
	m.pickItems = reports
	m.pickAt = 0
	m.onPick = func(mm *model, report string) tea.Cmd {
		rels, err := QuarantinablePaths(mm.env, report)
		if err != nil || len(rels) == 0 {
			mm.st = stMenu
			mm.status = styleOK.Render("nothing quarantinable in that report")
			return nil
		}
		preview := rels
		if len(preview) > 12 {
			preview = append(append([]string{}, rels[:12]...), fmt.Sprintf("… and %d more", len(rels)-12))
		}
		mm.confirms = backupConfirm(confirmStep{
			warning: fmt.Sprintf("%d file(s) will be MOVED out of the webroot:\n  %s\n\n"+
				"Core/plugin files in this list should be REPLACED afterwards\n"+
				"(clean-core / wp plugin install --force) or the site may break.",
				len(rels), strings.Join(preview, "\n  ")),
			phrase: "QUARANTINE",
		})
		mm.confirmAt = 0
		mm.input.SetValue("")
		mm.input.Focus()
		mm.st = stConfirm
		mm.onOK = func(m2 *model) tea.Cmd {
			m2.busy("Quarantining…")
			env, ev := m2.env, m2.events
			go func() {
				batch, n, err := QuarantineFiles(env, rels)
				if err != nil {
					ev <- failMsg{err}
					return
				}
				ev <- doneMsg{[]string{
					fmt.Sprintf("Quarantined %d file(s) → %s", n, filepath.Join(env.Quarantine, batch)),
					"Restore any time via the menu or: ratsweepr restore " + batch,
				}}
			}()
			return m2.listen()
		}
		return nil
	}
	return nil
}

func (m *model) doRestorePick() tea.Cmd {
	batches := ListBatches(m.env)
	if len(batches) == 0 {
		m.status = styleMed.Render("no quarantine batches yet")
		return nil
	}
	m.st = stPick
	m.pickTitle = "Pick a quarantine batch to restore"
	m.pickItems = batches
	m.pickAt = 0
	m.onPick = func(mm *model, batch string) tea.Cmd {
		mm.confirms = []confirmStep{{
			warning: "Files from batch " + batch + " will be moved back into the webroot.",
			phrase:  "RESTORE",
		}}
		mm.confirmAt = 0
		mm.input.SetValue("")
		mm.input.Focus()
		mm.st = stConfirm
		mm.onOK = func(m2 *model) tea.Cmd {
			m2.busy("Restoring…")
			env, ev := m2.env, m2.events
			go func() {
				n, err := RestoreBatch(env, batch)
				if err != nil {
					ev <- failMsg{err}
					return
				}
				ev <- doneMsg{[]string{fmt.Sprintf("Restored %d file(s) from batch %s", n, batch)}}
			}()
			return m2.listen()
		}
		return nil
	}
	return nil
}

func (m *model) doCleanCore() tea.Cmd {
	m.busy("Checking which core files fail verification…")
	env, ev := m.env, m.events
	go func() {
		sigs, _ := env.LoadSignatures()
		sc := NewScanner(env, sigs, nil, nil)
		failing, err := FailingCoreFiles(env, sc)
		if err != nil {
			ev <- failMsg{err}
			return
		}
		ev <- doneMsg{append([]string{"__cleancore__"}, failing...)}
	}()
	return m.listen()
}

func (m *model) doBaseline() tea.Cmd {
	m.busy("Hashing plugins & themes… (only do this on a KNOWN-CLEAN site)")
	env, ev := m.env, m.events
	go func() {
		n, err := BaselineGenerate(env, func(p string) { ev <- progressMsg(p) })
		if err != nil {
			ev <- failMsg{err}
			return
		}
		ev <- doneMsg{[]string{fmt.Sprintf("Stored %d baseline manifest(s) in %s", n, env.Baselines)}}
	}()
	return m.listen()
}

func (m *model) doBaselineVerify() tea.Cmd {
	m.busy("Verifying against baselines…")
	env, ev := m.env, m.events
	go func() {
		sigs, _ := env.LoadSignatures()
		sc := NewScanner(env, sigs,
			func(p string) { ev <- progressMsg(p) },
			func(f Finding) { ev <- findingMsg(f) })
		BaselineVerify(env, sc)
		ev <- doneMsg{[]string{"Full report: " + env.ReportPath}}
	}()
	return m.listen()
}

func (m *model) doSalts() tea.Cmd {
	m.confirms = backupConfirm(confirmStep{
		warning: "The 8 auth keys/salts in wp-config.php will be replaced.\n" +
			"All logged-in sessions (including any attacker's) become invalid.",
		phrase: "ROTATE",
	})
	m.confirmAt = 0
	m.input.SetValue("")
	m.input.Focus()
	m.st = stConfirm
	m.onOK = func(m2 *model) tea.Cmd {
		m2.busy("Rotating salts…")
		env, ev := m2.env, m2.events
		go func() {
			backup, err := ShuffleSalts(env)
			if err != nil {
				ev <- failMsg{err}
				return
			}
			ev <- doneMsg{[]string{"Salts rotated. Previous wp-config kept as " + backup}}
		}()
		return m2.listen()
	}
	return nil
}

// ------------------------------ views ----------------------------------------

func sevStyle(s string) lipgloss.Style {
	switch s {
	case SevHigh:
		return styleHigh
	case SevMed:
		return styleMed
	default:
		return styleInfo
	}
}

func (m *model) renderResults(footer []string) string {
	// intercept the clean-core handoff
	if len(footer) > 0 && footer[0] == "__cleancore__" {
		return m.renderCleanCoreConfirm(footer[1:])
	}
	var b strings.Builder
	high, med, info := 0, 0, 0
	for _, f := range m.findings {
		switch f.Sev {
		case SevHigh:
			high++
		case SevMed:
			med++
		case SevInfo:
			info++
		}
	}
	fmt.Fprintf(&b, "%s  %s  %s\n\n",
		styleHigh.Render(fmt.Sprintf("HIGH %d", high)),
		styleMed.Render(fmt.Sprintf("MED %d", med)),
		styleInfo.Render(fmt.Sprintf("INFO %d", info)))
	order := []string{SevHigh, SevMed, SevInfo, SevWarn}
	for _, sev := range order {
		for _, f := range m.findings {
			if f.Sev != sev {
				continue
			}
			fmt.Fprintf(&b, "%s %s %s\n     %s\n",
				sevStyle(sev).Render(fmt.Sprintf("%-4s", sev)),
				styleTag.Render(f.Cat), f.Item, styleDim.Render(f.Detail))
		}
	}
	if len(m.findings) == 0 {
		b.WriteString(styleOK.Render("No findings.") + "\n")
	}
	b.WriteString("\n")
	for _, l := range footer {
		b.WriteString(styleOK.Render("✓ ") + l + "\n")
	}
	if high+med > 0 {
		b.WriteString("\n" + styleDim.Render(
			"Next: review MED findings (heuristics can false-positive), make a full\n"+
				"backup, then quarantine confirmed findings from the menu."))
	}
	return b.String()
}

func (m *model) renderCleanCoreConfirm(failing []string) string {
	if len(failing) == 0 {
		m.st = stResults
		return styleOK.Render("✓ All core files already verify. Nothing to do.")
	}
	preview := failing
	if len(preview) > 12 {
		preview = append(append([]string{}, failing[:12]...), fmt.Sprintf("… and %d more", len(failing)-12))
	}
	m.confirms = backupConfirm(confirmStep{
		warning: fmt.Sprintf("%d core file(s) will be replaced with clean %s copies\n"+
			"(originals are quarantined first):\n  %s",
			len(failing), m.env.WPVersion, strings.Join(preview, "\n  ")),
		phrase: "REPLACE",
	})
	m.confirmAt = 0
	m.input.SetValue("")
	m.input.Focus()
	m.st = stConfirm
	m.onOK = func(m2 *model) tea.Cmd {
		m2.busy("Replacing failing core files…")
		env, ev := m2.env, m2.events
		go func() {
			n, err := CleanCore(env, failing, func(p string) { ev <- progressMsg(p) })
			if err != nil {
				ev <- failMsg{err}
				return
			}
			ev <- doneMsg{[]string{
				fmt.Sprintf("Replaced %d core file(s); originals quarantined.", n),
				"Plugins/themes: wp plugin install --force $(wp plugin list --field=name)",
			}}
		}()
		return m2.listen()
	}
	return ""
}

func (m *model) View() string {
	var b strings.Builder
	b.WriteString(renderBanner())
	b.WriteString(styleDim.Render(fmt.Sprintf(
		"  v%s (%s) · report-first · quarantine, never delete · no root\n", appVersion, gitCommit)))
	b.WriteString(styleDim.Render(fmt.Sprintf(
		"  site %s · WordPress %s\n\n", m.env.WPRoot, m.env.WPVersion)))

	switch m.st {
	case stMenu:
		for i, it := range m.menu {
			cur := "  "
			label := "  " + it.label
			if i == m.cursor {
				cur = styleCursor.Render("▸ ")
				label = " " + styleItemSel.Render(it.label)
			}
			b.WriteString("  " + cur + label + "\n")
		}
		if m.status != "" {
			b.WriteString("\n  " + m.status + "\n")
		}
		b.WriteString("\n" + styleDim.Render("  ↑/↓ move · enter select · q quit"))

	case stBusy:
		b.WriteString("  " + m.spin.View() + styleTitle.Render(" working…") + "\n\n")
		for _, l := range m.busyLog {
			b.WriteString(styleDim.Render("  "+l) + "\n")
		}
		if n := len(m.findings); n > 0 {
			b.WriteString(fmt.Sprintf("\n  findings so far: %s\n",
				styleMed.Render(fmt.Sprint(n))))
		}

	case stResults:
		if m.vpReady {
			m.vp.SetContent(m.resultTxt)
			b.WriteString(m.vp.View())
		} else {
			b.WriteString(m.resultTxt)
		}
		b.WriteString("\n" + styleDim.Render("  ↑/↓ scroll · enter/q back to menu"))

	case stConfirm:
		step := m.confirms[m.confirmAt]
		b.WriteString(styleWarnBox.Render(step.warning) + "\n\n")
		b.WriteString(fmt.Sprintf("  Type exactly %s to continue (Esc aborts):\n\n",
			styleTitle.Render(`"`+step.phrase+`"`)))
		b.WriteString("  " + m.input.View() + "\n")
		if m.status != "" {
			b.WriteString("\n  " + m.status + "\n")
		}

	case stPick:
		b.WriteString("  " + styleTitle.Render(m.pickTitle) + "\n\n")
		for i, it := range m.pickItems {
			cur := "  "
			label := "  " + it
			if i == m.pickAt {
				cur = styleCursor.Render("▸ ")
				label = " " + styleItemSel.Render(it)
			}
			b.WriteString("  " + cur + label + "\n")
		}
		b.WriteString("\n" + styleDim.Render("  ↑/↓ move · enter select · esc back"))
	}
	b.WriteString("\n")
	return b.String()
}

func runTUI(e *Env) error {
	p := tea.NewProgram(newModel(e), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

var _ = os.Stdout // keep os import if unused paths change
