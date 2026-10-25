// Package tui implements the interactive netwatch dashboard.
package tui

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

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
	tabHosts
	tabServices
	tabFindings
	tabHistory
	tabReport
	tabCount
)

var tabNames = []string{"exposures", "hosts", "services", "findings", "history", "report"}

// tabSpan is the rendered x-range of a tab label, so the mouse can hit-test it.
type tabSpan struct {
	from, to int
	tab      int
}

// detailView is the drill-down opened with enter: one host, service,
// exposure or finding, explained in full and scrolled independently.
type detailView struct {
	title string
	kind  string
	key   string
	vp    viewport.Model
}

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
		runID  int64 // non-zero when a specific historical run was opened
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
	// Tabs holding something that needs attention stay readable when not
	// selected, so the page you are on is not the only thing you can see.
	warnTab     = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Padding(0, 1)
	badTab      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).Padding(0, 1)
	rule        = lipgloss.NewStyle().Foreground(lipgloss.Color("236"))
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
	hosts   []model.Host

	// detail is the drill-down over the selected row; nil when closed.
	detail   *detailView
	bodyTop  int       // screen row where the body starts, measured in View
	tabSpans []tabSpan // rendered tab positions, for mouse clicks

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
	m.tables[tabHosts] = newTable([]table.Column{
		{Title: "Host", Width: 16}, {Title: "IP", Width: 15},
		{Title: "Ports", Width: 6}, {Title: "Public", Width: 7},
		{Title: "Advisories", Width: 24}, {Title: "Updates", Width: 8},
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
	// The default selection is bold-only, which reads as "no selection" on a
	// sparse row. A filled background makes the cursor obvious, which matters
	// because enter drills into whichever row is under it.
	st := table.DefaultStyles()
	st.Selected = st.Selected.
		Foreground(lipgloss.Color("230")).
		Background(lipgloss.Color("238")).
		Bold(true)
	t.SetStyles(st)
	return t
}

// SetProgram lets the model push progress out of the scan goroutine.
func (m *Model) SetProgram(p *tea.Program) { m.program = p }

// Run starts the program. Mouse is enabled so a row can be clicked as well as
// selected with the keyboard; both open the same detail view.
func Run(cfg *config.Config, engine *scan.Engine) error {
	m := New(cfg, engine)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
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

// loadRunCmd loads one specific historical run, for enter on the history tab.
func loadRunCmd(eng *scan.Engine, runID int64) tea.Cmd {
	return func() tea.Msg {
		res, err := eng.Load(runID)
		return loadedMsg{result: res, err: err, runID: runID}
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
		m.detail = nil
		if d := durationString(msg.result); d != "" {
			m.status = fmt.Sprintf("Scan finished in %ss  (s rescan)", d)
		} else {
			m.status = "Scan finished  (s rescan)"
		}
		m.rebuild()
		return m, historyCmd(m.engine)

	case loadedMsg:
		if msg.err != nil {
			m.status = "Could not load history: " + msg.err.Error()
			return m, nil
		}
		if msg.result != nil {
			m.result = msg.result
			m.detail = nil // the old drill-down refers to a different scan
			if msg.runID != 0 {
				m.status = fmt.Sprintf("Showing scan %d from %s  (r returns to the latest)",
					msg.runID, msg.result.Started)
			} else {
				m.status = fmt.Sprintf("Showing scan from %s  (s to scan now)", msg.result.Started)
			}
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

	case tea.MouseMsg:
		return m.handleMouse(msg)
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		return m, tea.Quit
	}
	// While a scan is in flight only cancel and quit are honoured: the tables
	// are about to be replaced anyway.
	if m.scanning && key != "esc" && key != "q" {
		return m, nil
	}

	if a, ok := scrollKeys(key); ok {
		m.scrollCurrent(a)
		return m, nil
	}

	switch key {
	case "q":
		if m.detail != nil { // forgiving: close the drill-down first
			m.detail = nil
			m.status = "Details closed  (q quits)"
			return m, nil
		}
		return m, tea.Quit

	case "esc":
		switch {
		case m.scanning:
			if m.cancel != nil {
				m.cancel()
			}
			m.status = "Cancelling scan…"
		case m.detail != nil:
			m.detail = nil
			m.status = "Details closed"
		default:
			return m, tea.Quit
		}
		return m, nil

	case "enter":
		return m.openDetail()
	case "[":
		return m.moveSelection(-1)
	case "]":
		return m.moveSelection(1)

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
		m.closeDetail()
		m.tab = (m.tab + 1) % tabCount
		return m, nil
	case "shift+tab", "left", "h":
		m.closeDetail()
		m.tab = (m.tab + tabCount - 1) % tabCount
		return m, nil
	}

	if len(msg.Runes) == 1 && msg.Runes[0] >= '1' && int(msg.Runes[0]-'0') <= tabCount {
		m.closeDetail()
		m.tab = int(msg.Runes[0] - '1')
		return m, nil
	}
	return m, nil
}

// closeDetail drops the drill-down; called whenever the screen changes
// underneath it, so a stale view never pretends to describe the current row.
func (m *Model) closeDetail() { m.detail = nil }

// ------------------------------------------------------------ scroll plumbing

type scrollAction int

const (
	scrollUp scrollAction = iota
	scrollDown
	scrollPageUp
	scrollPageDown
	scrollTop
	scrollBottom
)

// scrollKeys maps the bindings shared by every scrollable widget.
func scrollKeys(key string) (scrollAction, bool) {
	switch key {
	case "down", "j":
		return scrollDown, true
	case "up", "k":
		return scrollUp, true
	case "pgdown", "space", "f":
		return scrollPageDown, true
	case "pgup", "b":
		return scrollPageUp, true
	case "g", "home":
		return scrollTop, true
	case "G", "end":
		return scrollBottom, true
	}
	return scrollUp, false
}

// scrollCurrent applies a scroll action to whichever widget owns the screen:
// the open drill-down, else the report, else the current tab's table.
func (m *Model) scrollCurrent(a scrollAction) {
	if m.detail != nil {
		scrollViewport(&m.detail.vp, a)
		return
	}
	if m.tab == tabReport {
		scrollViewport(&m.reportVP, a)
		return
	}
	t := &m.tables[m.tab]
	switch a {
	case scrollDown:
		t.MoveDown(1)
	case scrollUp:
		t.MoveUp(1)
	case scrollPageDown:
		t.MoveDown(t.Height())
	case scrollPageUp:
		t.MoveUp(t.Height())
	case scrollTop:
		t.GotoTop()
	case scrollBottom:
		t.GotoBottom()
	}
}

func scrollViewport(v *viewport.Model, a scrollAction) {
	switch a {
	case scrollDown:
		v.LineDown(1)
	case scrollUp:
		v.LineUp(1)
	case scrollPageDown:
		v.PageDown()
	case scrollPageUp:
		v.PageUp()
	case scrollTop:
		v.GotoTop()
	case scrollBottom:
		v.GotoBottom()
	}
}

// ------------------------------------------------------------------- drilldown

// selection describes the row the cursor is on, in the form the drill-down
// needs. kind is host | service | exposure | finding | run.
func (m *Model) selection() (kind, key, title string, ok bool) {
	if m.result == nil || m.tab == tabReport {
		return "", "", "", false
	}
	idx := m.tables[m.tab].Cursor()
	if idx < 0 {
		// An empty table leaves the bubbles cursor at -1; nothing is selected.
		return "", "", "", false
	}
	switch m.tab {
	case tabHosts:
		if idx >= len(m.hosts) {
			return "", "", "", false
		}
		h := m.hosts[idx]
		return "host", h.IP, h.Label() + " · " + h.IP, true
	case tabServices:
		if idx >= len(m.services) {
			return "", "", "", false
		}
		s := m.services[idx]
		return "service", s.Key(), s.Label() + " · " + s.Key(), true
	case tabExposures:
		if idx >= len(m.public) {
			return "", "", "", false
		}
		e := m.public[idx]
		return "exposure", e.Target, e.Target + "  ·  " + e.Kind + " exposure", true
	case tabFindings:
		if idx >= len(m.findings) {
			return "", "", "", false
		}
		f := m.findings[idx]
		return "finding", f.Identity(),
			strings.ToUpper(orDash(f.Severity)) + "  ·  " + f.App + " " + f.Ref, true
	case tabHistory:
		if idx >= len(m.history) {
			return "", "", "", false
		}
		r := m.history[idx]
		return "run", fmt.Sprint(r.ID), "scan " + fmt.Sprint(r.ID) + " from " + r.Started, true
	}
	return "", "", "", false
}

// openDetail drills into the selected row.
func (m *Model) openDetail() (tea.Model, tea.Cmd) {
	kind, key, title, ok := m.selection()
	if !ok {
		m.status = "Nothing to show here"
		return m, nil
	}
	if kind == "run" { // history rows load that scan instead
		if m.engine == nil {
			m.status = "No database available"
			return m, nil
		}
		id, err := strconv.ParseInt(key, 10, 64)
		if err != nil {
			m.status = "Bad run id " + key
			return m, nil
		}
		m.detail = nil
		m.status = "Loading scan " + key + "…"
		return m, loadRunCmd(m.engine, id)
	}
	if m.result == nil {
		m.status = "No scan loaded yet"
		return m, nil
	}

	sections := m.detailSections(kind, key)
	if len(sections) == 0 {
		m.status = "No details available for that row"
		return m, nil
	}

	dv := &detailView{title: title, kind: kind, key: key}
	m.detail = dv
	dv.vp = viewport.New(m.detailWidth(), m.bodyHeight())
	dv.vp.SetContent(dv.header(m.detailWidth()) + "\n\n" + renderSections(sections, m.detailWidth()))
	m.status = "Details · esc back · [ ] previous/next row · j k scroll"
	return m, nil
}

// detailSections builds the drill-down for one row. It lives apart from
// openDetail so a resize can rebuild the same content at the new width.
func (m *Model) detailSections(kind, key string) []detailSection {
	if m.result == nil {
		return nil
	}
	switch kind {
	case "host":
		return hostDetail(m.result, key)
	case "service":
		return serviceDetail(m.result, key)
	case "exposure":
		if e, found := findExposure(m.public, key); found {
			return exposureDetail(m.result, e)
		}
	case "finding":
		if f, found := findFinding(m.findings, key); found {
			return findingDetail(m.result, f)
		}
	}
	return nil
}

// detailWidth is the width detail content is laid out at: the screen, but never
// so narrow that a label column leaves nothing for the value.
func (m *Model) detailWidth() int { return max(40, m.width) }

// refreshDetail re-renders the open drill-down after the screen changed size.
func (m *Model) refreshDetail() {
	if m.detail == nil {
		return
	}
	w, h := m.detailWidth(), m.bodyHeight()
	m.detail.vp.Width, m.detail.vp.Height = w, h
	if sections := m.detailSections(m.detail.kind, m.detail.key); len(sections) > 0 {
		m.detail.vp.SetContent(m.detail.header(w) + "\n\n" + renderSections(sections, w))
	}
}

// header labels the drill-down, so it is never ambiguous which row you are
// inside, and rules off the body. It is sized to the viewport exactly, since a
// line one cell too wide would wrap and shift everything below it.
func (d *detailView) header(width int) string {
	plain := d.kind + " · " + d.title
	return titleStyle.Render(plain) + " " + rule.Render(strings.Repeat("─", max(0, width-lipgloss.Width(plain)-1)))
}

// moveSelection steps the cursor and follows it with the drill-down, so [ and
// ] browse a list of hosts or advisories without leaving the detail view.
func (m *Model) moveSelection(delta int) (tea.Model, tea.Cmd) {
	if m.tab == tabReport || m.result == nil {
		return m, nil
	}
	t := &m.tables[m.tab]
	if len(t.Rows()) == 0 {
		return m, nil
	}
	if delta > 0 {
		t.MoveDown(1)
	} else {
		t.MoveUp(1)
	}
	return m.openDetail()
}

// selectRow puts the cursor exactly on row, using the same movement calls the
// keyboard uses so bubbles keeps its viewport in sync.
func (m *Model) selectRow(row int) {
	t := &m.tables[m.tab]
	if row < 0 {
		row = 0
	}
	if n := len(t.Rows()) - 1; row > n {
		row = n
	}
	t.GotoTop()
	t.MoveDown(row)
}

func findExposure(items []model.Exposure, target string) (model.Exposure, bool) {
	for _, e := range items {
		if e.Target == target {
			return e, true
		}
	}
	return model.Exposure{}, false
}

func findFinding(items []model.Finding, identity string) (model.Finding, bool) {
	for _, f := range items {
		if f.Identity() == identity {
			return f, true
		}
	}
	return model.Finding{}, false
}

// ----------------------------------------------------------------------- mouse

func (m *Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if msg.Action == tea.MouseActionRelease {
		return m, nil
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		m.scrollCurrent(scrollUp)
	case tea.MouseButtonWheelDown:
		m.scrollCurrent(scrollDown)
	case tea.MouseButtonLeft:
		return m.click(msg.X, msg.Y)
	}
	return m, nil
}

// click maps a cell onto the tab bar or onto a row in the current table.
func (m *Model) click(x, y int) (tea.Model, tea.Cmd) {
	if y == m.tabRowY() {
		for _, s := range m.tabSpans {
			if x >= s.from && x < s.to {
				m.closeDetail()
				m.tab = s.tab
				return m, nil
			}
		}
		return m, nil
	}
	if m.detail != nil || m.tab == tabReport || m.result == nil {
		return m, nil
	}
	row := y - m.bodyTop - 1 // the body's first line is the table's header row
	if row < 0 || row >= len(m.tables[m.tab].Rows()) {
		return m, nil
	}
	m.selectRow(row)
	return m.openDetail()
}

// ------------------------------------------------------------------ projection

// rebuild re-derives every table's rows (and the report text) from the result.
func (m *Model) rebuild() {
	m.services = nil
	m.public = nil
	m.findings = nil
	m.hosts = nil
	m.reportSrc = ""

	if m.result != nil {
		m.services = m.result.Services()
		m.public = m.result.PublicExposures()
		m.findings = append([]model.Finding(nil), m.result.Findings...)
		report.SortFindings(m.findings)
		m.hosts = sortHosts(m.result, m.result.Hosts)
		m.reportSrc = report.ToMarkdown(m.result)
	}

	m.tables[tabExposures].SetRows(exposureRows(m.public))
	m.tables[tabHosts].SetRows(hostRows(m.result, m.hosts))
	m.tables[tabServices].SetRows(serviceRows(m.services))
	m.tables[tabFindings].SetRows(findingRows(m.findings))
	m.tables[tabHistory].SetRows(historyRows(m.history))
	m.reportVP.SetContent(orText(m.reportSrc, "No scan loaded yet. Press s to run one."))

	for i := range m.tables {
		n := len(m.tables[i].Rows())
		if n == 0 {
			continue // no cursor to place on an empty page
		}
		// SetRows can leave the cursor out of range at either end: a table
		// that was empty when it got rows is stuck at -1.
		if c := m.tables[i].Cursor(); c < 0 || c >= n {
			m.tables[i].SetCursor(min(n-1, max(0, c)))
		}
	}
}

// sortHosts puts the hosts a human would open first on top: anything
// internet-facing, then anything with the worst advisories, then by address.
func sortHosts(r *model.ScanResult, hosts []model.Host) []model.Host {
	out := append([]model.Host(nil), hosts...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if pa, pb := publicCount(a), publicCount(b); pa != pb {
			return pa > pb
		}
		if ra, rb := worstRankOnHost(r, a), worstRankOnHost(r, b); ra != rb {
			return ra < rb
		}
		return a.IP < b.IP
	})
	return out
}

func publicCount(h model.Host) int {
	n := 0
	for _, s := range h.Services {
		if s.Reach == model.ReachPublic {
			n++
		}
	}
	return n
}

// worstRankOnHost is the triage rank of the worst advisory anywhere on a host;
// unranked (no advisories) sorts last.
func worstRankOnHost(r *model.ScanResult, h model.Host) int {
	worst := 99
	for _, s := range h.Services {
		for _, f := range vulnerabilities(findingsFor(r, s.Key())) {
			if rf := report.SeverityRank(f.Severity); rf < worst {
				worst = rf
			}
		}
	}
	return worst
}

// hostRows renders the hosts page. The counts repeat what the drill-down says,
// so a row is triageable before it is opened.
func hostRows(r *model.ScanResult, hosts []model.Host) []table.Row {
	rows := make([]table.Row, 0, len(hosts))
	if r == nil {
		return rows
	}
	for _, h := range hosts {
		var all []model.Finding
		for _, s := range h.Services {
			all = append(all, findingsFor(r, s.Key())...)
		}
		vulns := vulnerabilities(all)
		updates := 0
		for _, s := range h.Services {
			if _, ok := updateFinding(r, s.Key(), s.App); ok {
				updates++
			}
		}
		advisories := orText(severityTally(vulns), "-")
		if len(vulns) > 0 {
			advisories = fmt.Sprintf("%d · %s", len(vulns), severityTally(vulns))
		}
		rows = append(rows, table.Row{
			h.Label(), h.IP, fmt.Sprint(len(h.Services)), fmt.Sprint(publicCount(h)),
			clip(advisories, 24), fmt.Sprint(updates),
		})
	}
	return rows
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

// durationString is the scan's wall time in seconds, or "" when no scan
// actually measured it. Showing "in ?s" invites the question the answer is
// "we do not know", so the summary drops the segment instead.
func durationString(result *model.ScanResult) string {
	if result == nil {
		return ""
	}
	if v, ok := result.Stats["duration_s"]; ok {
		return fmt.Sprint(v)
	}
	// Runs predating the stats column still carry their start and finish.
	started, err1 := time.Parse(time.RFC3339, result.Started)
	finished, err2 := time.Parse(time.RFC3339, result.Finished)
	if err1 == nil && err2 == nil && !finished.Before(started) {
		return strings.TrimSuffix(fmt.Sprint(finished.Sub(started).Round(time.Second)), "s")
	}
	return ""
}

// ---------------------------------------------------------------------- layout

// The screen is fixed: title, tab bar, summary, [progress], body, help, status.
// Nothing in the chrome is allowed to wrap, because the mouse maps a click to a
// row by counting lines from the top; bodyTop is measured in View for that.

func (m *Model) resize() {
	body := m.bodyHeight()
	for i := range m.tables {
		m.tables[i].SetWidth(m.width)
		m.tables[i].SetHeight(body)
	}
	m.reportVP.Width = m.width
	m.reportVP.Height = body
	m.refreshDetail()
	m.bar.Width = min(60, max(20, m.width-12))
}

// bodyHeight is the room left for the table, report, or open drill-down.
func (m *Model) bodyHeight() int {
	body := m.height - m.headerLines() - 2 // help line + status line
	if body < 3 {
		body = 3
	}
	return body
}

// headerLines counts the fixed chrome above the body.
func (m *Model) headerLines() int {
	header := 3 // title + tab bar + summary
	if m.scanning {
		header++
	}
	return header
}

// tabRowY is the screen row holding the tab bar, so a click there can switch
// pages. It is fixed: the title is always the first line.
func (m *Model) tabRowY() int { return 1 }

// tabLine renders the page bar: numbered, with the number of rows on each page
// so you can see what is where without cycling through them, and coloured when
// a page holds something that needs attention. It also records where each
// label landed so the mouse can hit-test it.
func (m *Model) tabLine() string {
	m.tabSpans = nil
	var b strings.Builder
	x := 0
	for i, name := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if n := m.tabCount(i); n > 0 {
			label += " " + fmt.Sprint(n)
		}
		style := inactiveTab
		switch {
		case i == m.tab:
			style = activeTab
		case m.tabAttention(i) == attentionBad:
			style = badTab
		case m.tabAttention(i) == attentionWarn:
			style = warnTab
		}
		width := lipgloss.Width(label) + 2 // the padding every tab style adds
		if x+width > m.width {
			break // dropping the tail beats wrapping and shifting every row below
		}
		m.tabSpans = append(m.tabSpans, tabSpan{from: x, to: x + width, tab: i})
		b.WriteString(style.Render(label))
		x += width
	}
	return b.String()
}

func (m *Model) tabCount(tab int) int {
	switch tab {
	case tabExposures:
		return len(m.public)
	case tabHosts:
		return len(m.hosts)
	case tabServices:
		return len(m.services)
	case tabFindings:
		return len(m.findings)
	case tabHistory:
		return len(m.history)
	}
	return 0
}

type attention int

const (
	attentionNone attention = iota
	attentionWarn
	attentionBad
)

// tabAttention colours a page by its worst item, so the red "2" on exposures
// is visible from the hosts page rather than only when you land on it.
func (m *Model) tabAttention(tab int) attention {
	if m.result == nil {
		return attentionNone
	}
	switch tab {
	case tabExposures:
		for _, e := range m.public {
			if e.Public && e.Verified {
				return attentionBad
			}
		}
		if len(m.public) > 0 {
			return attentionWarn
		}
	case tabHosts, tabServices:
		for _, s := range m.services {
			if s.Reach == model.ReachPublic {
				return attentionBad
			}
		}
		for _, s := range m.services {
			if s.Reach == model.ReachTailnet {
				return attentionWarn
			}
		}
	case tabFindings:
		worst := attentionNone
		for _, f := range m.findings {
			if f.Kind == "update" {
				worst = maxAttention(worst, attentionWarn)
				continue
			}
			if report.SeverityRank(f.Severity) <= 1 {
				return attentionBad
			}
			worst = maxAttention(worst, attentionWarn)
		}
		return worst
	}
	return attentionNone
}

func maxAttention(a, b attention) attention {
	if a > b {
		return a
	}
	return b
}

// View renders the whole screen. The line count matters: the mouse maps a
// click onto a row using bodyTop, so the parts are joined rather than each
// getting a trailing newline of its own.
func (m *Model) View() string {
	if m.width == 0 {
		return "starting…"
	}

	header := m.viewHeader()
	m.bodyTop = lipgloss.Height(header) // the body begins on the next line

	return strings.Join([]string{
		header,
		m.viewBody(),
		helpStyle.Render(clip(m.helpLine(), m.width)),
		statusStyle.Render(clip(m.status, m.width)),
	}, "\n")
}

func (m *Model) viewHeader() string {
	lines := []string{
		titleStyle.Render("netwatch") + " " +
			subtitleStyle.Render("exposure · vuln tracker"),
		m.tabLine(),
		m.summaryLine(),
	}
	if m.scanning {
		lines = append(lines, m.bar.ViewAs(float64(m.pct())/100.0))
	}
	return strings.Join(lines, "\n")
}

// summaryLine is the at-a-glance count row. It is assembled left to right and
// stops at the edge of the screen, so it can never wrap into the body.
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
	if len(m.findings) > 0 {
		findStyle = warnStyle
	}

	type seg struct {
		plain    string
		rendered string
	}
	add := func(label, value string, style lipgloss.Style) seg {
		return seg{plain: label + value, rendered: subtitleStyle.Render(label) + style.Render(value)}
	}
	segs := []seg{
		add("public IP ", orDash(r.PublicIP), publicStyle),
		add(" hosts ", fmt.Sprint(len(r.Hosts)), okStyle),
		add(" services ", fmt.Sprint(len(m.services)), okStyle),
		add(" public ", fmt.Sprint(len(m.public)), publicStyle),
		add(" findings ", fmt.Sprint(len(m.findings)), findStyle),
		add(" tailnet ", fmt.Sprint(counts[model.ReachTailnet]), subtitleStyle),
	}
	if d := durationString(r); d != "" {
		segs = append(segs, add(" in "+d+"s", "", subtitleStyle))
	}

	var b strings.Builder
	used := 0
	for _, s := range segs {
		if used+lipgloss.Width(s.plain) > m.width {
			break
		}
		b.WriteString(s.rendered)
		used += lipgloss.Width(s.plain)
	}
	return b.String()
}

func (m *Model) viewBody() string {
	if m.detail != nil {
		return m.detail.vp.View()
	}
	if m.tab == tabReport {
		return m.reportVP.View()
	}
	return m.tables[m.tab].View()
}

func (m *Model) helpLine() string {
	if m.scanning {
		return "esc cancel scan · progress below"
	}
	if m.detail != nil {
		return "esc close details · [ ] previous/next row · j k pgup pgdn scroll · q quit"
	}
	base := "q quit · s scan · S full scan · tab/←→ or 1-6 pages · ↑↓ move · enter details · e export md · E export json"
	switch m.tab {
	case tabHistory:
		return "enter open that scan · d prune (keep 50) · " + base
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
