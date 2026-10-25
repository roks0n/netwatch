// Package tui implements the interactive netwatch dashboard.
package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/roks0n/netwatch/internal/config"
	"github.com/roks0n/netwatch/internal/model"
	"github.com/roks0n/netwatch/internal/report"
	"github.com/roks0n/netwatch/internal/scan"
	"github.com/roks0n/netwatch/internal/store"
)

// Tabs, in display order.
const (
	tabExposures = iota
	tabServices
	tabFindings
	tabHistory
	tabReport
	tabCount
)

var tabNames = []string{"exposures", "services", "findings", "history", "report"}

// Messages exchanged with the scan goroutine.
type (
	scanProgressMsg struct {
		pct int
		msg string
	}
	scanDoneMsg struct {
		result *model.ScanResult
	}
	loadedMsg struct {
		result *model.ScanResult
		err    error
	}
	historyMsg struct {
		rows []store.RunSummary
		err  error
	}
	exportMsg struct {
		path string
		err  error
	}
	pruneMsg struct {
		err error
	}
)

// Style palette. Colors live in the chrome (headers, tab bar, status) and
// never inside table cells, where they would disturb column alignment.
var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	subtitleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	activeTab     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("99")).Padding(0, 1)
	inactiveTab = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Padding(0, 1)
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	badStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	helpStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
)

// Model is the bubbletea model driving the whole dashboard. Methods use a
// pointer receiver because the scan goroutine posts progress back into it.
type Model struct {
	cfg     *config.Config
	engine  *scan.Engine
	program *tea.Program

	result  *model.ScanResult
	history []store.RunSummary

	tab    int
	width  int
	height int

	tables   [tabHistory + 1]table.Model
	reportVP viewport.Model
	bar      progress.Model

	status   string
	scanning bool
	lastPct  int
	cancel   context.CancelFunc

	// cached projections of result, kept in sync with the table rows
	services  []model.Service
	public    []model.Exposure
	findings  []model.Finding
	reportSrc string
}

// New builds the initial model.
func New(cfg *config.Config, engine *scan.Engine) *Model {
	m := &Model{cfg: cfg, engine: engine, status: "Loading last scan…"}

	m.tables[tabExposures] = newTable([]table.Column{
		{Title: "Target", Width: 36}, {Title: "Kind", Width: 10},
		{Title: "Verified", Width: 8}, {Title: "App", Width: 18},
		{Title: "Detail", Width: 44},
	})
	m.tables[tabServices] = newTable([]table.Column{
		{Title: "Host", Width: 16}, {Title: "Port", Width: 6},
		{Title: "App", Width: 18}, {Title: "Version", Width: 12},
		{Title: "Reach", Width: 8}, {Title: "Evidence", Width: 42},
	})
	m.tables[tabFindings] = newTable([]table.Column{
		{Title: "Severity", Width: 9}, {Title: "Kind", Width: 10},
		{Title: "App", Width: 16}, {Title: "Ref", Width: 16},
		{Title: "Installed", Width: 10}, {Title: "Fixed", Width: 10},
		{Title: "Title", Width: 40},
	})
	m.tables[tabHistory] = newTable([]table.Column{
		{Title: "ID", Width: 5}, {Title: "Started", Width: 20},
		{Title: "Public IP", Width: 16}, {Title: "Services", Width: 8},
		{Title: "Public", Width: 6}, {Title: "Findings", Width: 8},
	})

	m.reportVP = viewport.New(80, 24)
	m.bar = progress.New(progress.WithDefaultGradient(), progress.WithWidth(60))
	return m
}

func newTable(cols []table.Column) table.Model {
	t := table.New(table.WithColumns(cols))
	t.SetHeight(1)
	return t
}

// SetProgram lets the model push progress out of the scan goroutine.
func (m *Model) SetProgram(p *tea.Program) { m.program = p }

// Run starts the program.
func Run(cfg *config.Config, engine *scan.Engine) error {
	m := New(cfg, engine)
	p := tea.NewProgram(m, tea.WithAltScreen())
	m.SetProgram(p)
	_, err := p.Run()
	return err
}

// ------------------------------------------------------------------- commands

func (m *Model) startScan(opts scan.Options) tea.Cmd {
	if m.scanning {
		return nil
	}
	m.scanning = true
	m.status = "Starting scan…"
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	eng := m.engine
	prog := m.program
	return func() tea.Msg {
		res := eng.Scan(ctx, opts, func(pct int, msg string) {
			if prog != nil {
				prog.Send(scanProgressMsg{pct, msg})
			}
		})
		return scanDoneMsg{res}
	}
}

func latestCmd(eng *scan.Engine) tea.Cmd {
	return func() tea.Msg {
		res, err := eng.Latest()
		return loadedMsg{result: res, err: err}
	}
}

func historyCmd(eng *scan.Engine) tea.Cmd {
	return func() tea.Msg {
		rows, err := eng.History(25)
		return historyMsg{rows: rows, err: err}
	}
}

func exportCmd(eng *scan.Engine, cfg *config.Config, result *model.ScanResult, format string) tea.Cmd {
	return func() tea.Msg {
		if result == nil {
			return exportMsg{err: fmt.Errorf("no scan loaded")}
		}
		path, err := report.Write(result, cfg.ReportDir(), format, "")
		return exportMsg{path: path, err: err}
	}
}

func pruneCmd(eng *scan.Engine) tea.Cmd {
	return func() tea.Msg {
		if eng.Store == nil {
			return pruneMsg{}
		}
		return pruneMsg{err: eng.Store.Prune(50)}
	}
}

// --------------------------------------------------------------------- update

// Init loads the most recent scan so the dashboard is useful immediately.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(latestCmd(m.engine), historyCmd(m.engine))
}

// Update handles every message. Receiver is a pointer: the scan goroutine
// reports progress long after Init returned.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		return m, nil

	case scanProgressMsg:
		m.status = fmt.Sprintf("%3d%% %s", msg.pct, msg.msg)
		m.lastPct = msg.pct
		return m, nil

	case scanDoneMsg:
		m.scanning = false
		m.cancel = nil
		m.result = msg.result
		m.status = fmt.Sprintf("Scan finished in %ss  (s rescan)", durationString(msg.result))
		m.rebuild()
		return m, historyCmd(m.engine)

	case loadedMsg:
		if msg.err != nil {
			m.status = "Could not load history: " + msg.err.Error()
			return m, nil
		}
		if msg.result != nil {
			m.result = msg.result
			m.status = fmt.Sprintf("Showing scan from %s  (s to scan now)", msg.result.Started)
			m.rebuild()
			return m, nil
		}
		// Zero-touch first run: nobody configures netwatch before its first
		// scan, so start one straight away instead of showing an empty shell.
		m.rebuild()
		m.status = "No history yet — running the first scan"
		return m, m.startScan(scan.Options{})

	case historyMsg:
		if msg.err == nil {
			m.history = msg.rows
		}
		m.rebuild()
		return m, nil

	case exportMsg:
		if msg.err != nil {
			m.status = "Export failed: " + msg.err.Error()
		} else {
			m.status = "Saved " + msg.path
		}
		return m, nil

	case pruneMsg:
		if msg.err != nil {
			m.status = "Prune failed: " + msg.err.Error()
		} else {
			m.status = "Kept the 50 most recent scans"
		}
		return m, historyCmd(m.engine)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "q", "esc":
		if m.scanning {
			if m.cancel != nil {
				m.cancel()
			}
			m.status = "Cancelling scan…"
			return m, nil
		}
		return m, tea.Quit

	case "s":
		return m, m.startScan(scan.Options{})
	case "S":
		return m, m.startScan(scan.Options{Full: true})
	case "r":
		return m, latestCmd(m.engine)
	case "e":
		return m, exportCmd(m.engine, m.cfg, m.result, "md")
	case "E":
		return m, exportCmd(m.engine, m.cfg, m.result, "json")
	case "d":
		return m, pruneCmd(m.engine)

	case "tab", "right", "l":
		m.tab = (m.tab + 1) % tabCount
		return m, nil
	case "shift+tab", "left", "h":
		m.tab = (m.tab + tabCount - 1) % tabCount
		return m, nil
	case "1", "2", "3", "4", "5":
		m.tab = int(msg.Runes[0] - '1')
		return m, nil
	}

	// Scrolling keys act on whichever widget owns the current tab.
	if m.tab == tabReport {
		switch msg.String() {
		case "down", "j":
			m.reportVP.LineDown(1)
		case "up", "k":
			m.reportVP.LineUp(1)
		case "pgdown", "space", "f":
			m.reportVP.PageDown()
		case "pgup", "b":
			m.reportVP.PageUp()
		case "g", "home":
			m.reportVP.GotoTop()
		case "G", "end":
			m.reportVP.GotoBottom()
		}
		return m, nil
	}

	t := &m.tables[m.tab]
	switch msg.String() {
	case "down", "j":
		t.MoveDown(1)
	case "up", "k":
		t.MoveUp(1)
	case "pgdown", "space", "f":
		t.MoveDown(t.Height())
	case "pgup", "b":
		t.MoveUp(t.Height())
	case "g", "home":
		t.GotoTop()
	case "G", "end":
		t.GotoBottom()
	}
	return m, nil
}

// ------------------------------------------------------------------ projection

// rebuild re-derives every table's rows (and the report text) from the result.
func (m *Model) rebuild() {
	m.services = nil
	m.public = nil
	m.findings = nil
	m.reportSrc = ""

	if m.result != nil {
		m.services = m.result.Services()
		m.public = m.result.PublicExposures()
		m.findings = append([]model.Finding(nil), m.result.Findings...)
		report.SortFindings(m.findings)
		m.reportSrc = report.ToMarkdown(m.result)
	}

	m.tables[tabExposures].SetRows(exposureRows(m.public))
	m.tables[tabServices].SetRows(serviceRows(m.services))
	m.tables[tabFindings].SetRows(findingRows(m.findings))
	m.tables[tabHistory].SetRows(historyRows(m.history))
	m.reportVP.SetContent(orText(m.reportSrc, "No scan loaded yet. Press s to run one."))

	for i := range m.tables {
		if m.tables[i].Cursor() >= len(m.tables[i].Rows()) {
			m.tables[i].SetCursor(max(0, len(m.tables[i].Rows())-1))
		}
	}
}

func exposureRows(items []model.Exposure) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, e := range items {
		verified := "advisory"
		if e.Verified {
			verified = "yes"
		}
		rows = append(rows, table.Row{e.Target, e.Kind, verified, e.App, clip(e.Detail, 60)})
	}
	return rows
}

func serviceRows(items []model.Service) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, s := range items {
		evidence := strings.Join(s.Evidence, "; ")
		rows = append(rows, table.Row{
			s.IP, fmt.Sprint(s.Port), s.App, s.Version, reachLabel(s.Reach), clip(evidence, 60),
		})
	}
	return rows
}

func findingRows(items []model.Finding) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, f := range items {
		rows = append(rows, table.Row{
			f.Severity, f.Kind, f.App, f.Ref, f.Installed, f.Fixed, clip(f.Title, 70),
		})
	}
	return rows
}

func historyRows(items []store.RunSummary) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, r := range items {
		rows = append(rows, table.Row{
			fmt.Sprint(r.ID), r.Started, r.PublicIP,
			fmt.Sprint(r.Services), fmt.Sprint(r.Public), fmt.Sprint(r.Findings),
		})
	}
	return rows
}

func reachLabel(r model.Reach) string {
	switch r {
	case model.ReachPublic:
		return "PUBLIC"
	case model.ReachTailnet:
		return "tailnet"
	case model.ReachLAN:
		return "lan"
	default:
		return "?"
	}
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func orText(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func durationString(result *model.ScanResult) string {
	if result == nil {
		return "?"
	}
	if v, ok := result.Stats["duration_s"]; ok {
		return fmt.Sprint(v)
	}
	return "?"
}

// ---------------------------------------------------------------------- layout

func (m *Model) resize() {
	header := m.headerLines()
	footer := 2 // help line + status line
	body := m.height - header - footer
	if body < 3 {
		body = 3
	}
	for i := range m.tables {
		m.tables[i].SetWidth(m.width)
		m.tables[i].SetHeight(body)
	}
	m.reportVP.Width = m.width
	m.reportVP.Height = body
	m.bar.Width = min(60, max(20, m.width-12))
}

// headerLines renders the fixed chrome above the body and returns the whole
// view; the count of lines is derived here so resize stays honest.
func (m *Model) headerLines() int {
	header := 2 // title + summary
	if m.scanning {
		header++
	}
	return header
}

// View renders the whole screen.
func (m *Model) View() string {
	if m.width == 0 {
		return "starting…"
	}

	var b strings.Builder
	b.WriteString(m.viewHeader() + "\n")
	b.WriteString(m.viewBody() + "\n")
	b.WriteString(helpStyle.Render(m.helpLine()) + "\n")
	b.WriteString(statusStyle.Render(clip(m.status, m.width)) + "\n")
	return b.String()
}

func (m *Model) viewHeader() string {
	title := titleStyle.Render("netwatch") + " " +
		subtitleStyle.Render("exposure · vuln tracker")

	tabs := make([]string, 0, tabCount)
	for i, name := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if i == m.tab {
			tabs = append(tabs, activeTab.Render(label))
		} else {
			tabs = append(tabs, inactiveTab.Render(label))
		}
	}
	right := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
	head := lipgloss.JoinHorizontal(lipgloss.Top, title, "  ", right)

	head += "\n" + m.summaryLine()
	if m.scanning {
		head += "\n" + m.bar.ViewAs(float64(m.pct())/100.0)
	}
	return head
}

func (m *Model) summaryLine() string {
	if m.result == nil {
		return subtitleStyle.Render("no scan loaded")
	}
	r := m.result
	counts := r.CountReach()
	publicStyle := okStyle
	if counts[model.ReachPublic] > 0 {
		publicStyle = badStyle
	}
	findStyle := subtitleStyle
	if len(r.Findings) > 0 {
		findStyle = warnStyle
	}
	parts := []string{
		subtitleStyle.Render("public IP "),
		publicStyle.Render(orDash(r.PublicIP)),
		subtitleStyle.Render("  hosts "),
		okStyle.Render(fmt.Sprint(len(r.Hosts))),
		subtitleStyle.Render("  services "),
		okStyle.Render(fmt.Sprint(len(m.services))),
		subtitleStyle.Render("  public "),
		publicStyle.Render(fmt.Sprint(len(m.public))),
		subtitleStyle.Render("  findings "),
		findStyle.Render(fmt.Sprint(len(m.findings))),
		subtitleStyle.Render("  " + durationString(r) + "s"),
	}
	return strings.Join(parts, "")
}

func (m *Model) viewBody() string {
	if m.tab == tabReport {
		return m.reportVP.View()
	}
	return m.tables[m.tab].View()
}

func (m *Model) helpLine() string {
	base := "q quit · s scan · S full scan · tab/←→ switch · ↑↓ move · e export md · E export json"
	if m.scanning {
		return "esc cancel scan · " + base
	}
	switch m.tab {
	case tabReport:
		return "r reload · " + base
	case tabHistory:
		return "d prune (keep 50) · " + base
	default:
		return "r reload · " + base
	}
}

func (m *Model) pct() int { return m.lastPct }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
