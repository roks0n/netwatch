package tui

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/roks0n/netwatch/internal/scan"
	"github.com/roks0n/netwatch/internal/store"
)

// newTestModel is a rendered model over the detail fixture: screen-sized, with
// rows in every table, so layout and mouse mapping can be asserted honestly.
func newTestModel(t *testing.T) *Model {
	t.Helper()
	m := New(nil, nil)
	m.width, m.height = 100, 40
	m.result = fixture()
	m.history = []store.RunSummary{
		{ID: 14, Started: "2026-10-25T12:00:00Z", PublicIP: "203.0.113.7", Services: 4, Public: 2, Findings: 5},
		{ID: 13, Started: "2026-10-24T22:09:33Z", PublicIP: "203.0.113.7", Services: 3, Public: 2, Findings: 1},
	}
	m.rebuild()
	m.resize()
	return m
}

// ---------------------------------------------------------------------- tab bar

func TestTabLineNamesEveryPageWithItsCount(t *testing.T) {
	m := newTestModel(t)
	line := m.tabLine()
	for _, want := range []string{
		"exposures 2", "hosts 3", "services 4", "findings 5", "history 2", "report",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("tab bar is missing %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "1 exposures") {
		t.Errorf("tab labels should not carry numbers:\n%s", line)
	}
	if w := lipgloss.Width(line); w > m.width {
		t.Errorf("tab bar is %d wide, screen is %d", w, m.width)
	}
	if len(m.tabSpans) != tabCount {
		t.Fatalf("recorded %d spans, want %d", len(m.tabSpans), tabCount)
	}
	for i, s := range m.tabSpans {
		if s.tab != i {
			t.Errorf("span %d holds tab %d", i, s.tab)
		}
		if s.to <= s.from {
			t.Errorf("span %d is empty: %d..%d", i, s.from, s.to)
		}
		if i > 0 && s.from != m.tabSpans[i-1].to+2 {
			t.Errorf("span %d starts at %d, previous ended at %d, want a 2-column gap",
				i, s.from, m.tabSpans[i-1].to)
		}
	}
}

func TestTabLineDropsWhatDoesNotFit(t *testing.T) {
	m := newTestModel(t)
	m.width = 24
	line := m.tabLine()
	if w := lipgloss.Width(line); w > m.width {
		t.Errorf("tab bar is %d wide on a %d column screen: %q", w, m.width, line)
	}
	if len(m.tabSpans) >= tabCount {
		t.Errorf("expected the bar to drop tabs, kept %d of %d", len(m.tabSpans), tabCount)
	}
	if len(m.tabSpans) == 0 {
		t.Error("the current page must always be visible")
	}
}

// ansiRE matches SGR escape sequences, enough to read back rendered chrome.
var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

func TestTabBarIsBoxedAndEveryLineIsClickable(t *testing.T) {
	m := newTestModel(t)
	bar := stripANSI(m.tabLine())
	lines := strings.Split(bar, "\n")
	if len(lines) != 3 {
		t.Fatalf("tab bar is %d lines, want 3:\n%s", len(lines), bar)
	}
	box := func(label string) (string, string) {
		w := lipgloss.Width(label) + 2 // one column of padding on each side
		return "╭" + strings.Repeat("─", w) + "╮", "╰" + strings.Repeat("─", w) + "╯"
	}
	// Every tab is a complete box with padding: a top border, a spaced label,
	// and a bottom border — the count rides along as a number, not a fill.
	for _, label := range []string{"exposures 2", "report"} { // active, inactive
		top, bottom := box(label)
		if !strings.Contains(lines[0], top) {
			t.Errorf("tab bar top row lost %q:\n%s", top, lines[0])
		}
		if !strings.Contains(lines[1], "│ "+label+" │") {
			t.Errorf("tab bar label row lost the padding around %q:\n%s", label, lines[1])
		}
		if !strings.Contains(lines[2], bottom) {
			t.Errorf("tab bar bottom row lost %q:\n%s", bottom, lines[2])
		}
	}

	// A click must select the tab on any of the bar's three lines, and a
	// click in the gap between tabs must select nothing.
	m.View() // records the tab spans
	for _, y := range []int{m.tabRowY(), m.tabRowY() + 1, m.tabRowY() + 2} {
		m.tab = tabExposures
		target := m.tabSpans[tabServices]
		m.click(target.from, y)
		if m.tab != tabServices {
			t.Errorf("click at (%d,%d) selected tab %d, want %d", target.from, y, m.tab, tabServices)
		}
		m.click(target.to+1, y) // the gap after the tab
		if m.tab != tabServices {
			t.Errorf("click in the gap at (%d,%d) moved to tab %d", target.to+1, y, m.tab)
		}
	}
}

func TestTabAttentionPointsAtTheWorstPage(t *testing.T) {
	m := newTestModel(t)
	if got := m.tabAttention(tabExposures); got != attentionBad {
		t.Errorf("exposures = %v, want bad (a verified public forward)", got)
	}
	if got := m.tabAttention(tabFindings); got != attentionBad {
		t.Errorf("findings = %v, want bad (a critical advisory)", got)
	}
	if got := m.tabAttention(tabReport); got != attentionNone {
		t.Errorf("report = %v, want none", got)
	}

	m.result = nil
	if got := m.tabAttention(tabExposures); got != attentionNone {
		t.Errorf("with no scan, exposures = %v, want none", got)
	}
}

func TestTabAttentionIsQuietWhenClean(t *testing.T) {
	m := newTestModel(t)
	clean := fixture()
	clean.Findings = nil
	for i := range clean.Exposures {
		clean.Exposures[i].Public = false
		clean.Exposures[i].Verified = false
	}
	m.result = clean
	m.rebuild()
	if got := m.tabAttention(tabFindings); got != attentionNone {
		t.Errorf("findings = %v, want none", got)
	}
	if got := m.tabAttention(tabExposures); got != attentionNone {
		t.Errorf("exposures = %v, want none", got)
	}
}

// ---------------------------------------------------------------------- layout

func TestViewRowsLineUpWithBodyTop(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	out := m.View()
	want := m.headerLines() + m.bodyHeight() + 2 // + help + status
	if got := lipgloss.Height(out); got != want {
		t.Errorf("screen is %d rows, want %d\n%s", got, want, out)
	}
	if m.bodyTop != m.headerLines() {
		t.Errorf("bodyTop = %d, header is %d rows", m.bodyTop, m.headerLines())
	}
}

func TestNarrowScreenStillHasAUsableBody(t *testing.T) {
	m := newTestModel(t)
	m.width, m.height = 30, 8
	m.resize()
	if h := m.bodyHeight(); h < 3 {
		t.Errorf("body height = %d, want at least 3", h)
	}
	if out := m.View(); out == "" {
		t.Error("empty view")
	}
}

func TestHeadingsAndHelpMentionTheNewAffordances(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	if !strings.Contains(m.View(), "exposures") {
		t.Error("the tab bar must be on screen, not behind a keypress")
	}
	if !strings.Contains(m.helpLine(), "enter") {
		t.Errorf("help should advertise the drill-down: %q", m.helpLine())
	}
}

// ----------------------------------------------------------------------- mouse

func TestClickingTabSwitchesPage(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabExposures
	m.View() // records the tab spans
	target := m.tabSpans[tabFindings]
	m.click(target.from, m.tabRowY())
	if m.tab != tabFindings {
		t.Errorf("clicked findings, tab = %d", m.tab)
	}
}

func TestClickingARowOpensItsDetail(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	m.View()

	m.click(5, m.bodyTop+1) // first row under the table's header
	if m.detail == nil {
		t.Fatal("clicking a row opened nothing")
	}
	if m.detail.kind != "service" || m.detail.key != "192.0.2.10:51413/tcp" {
		t.Errorf("opened %s %s, want the first service", m.detail.kind, m.detail.key)
	}
	if got := m.tables[tabServices].Cursor(); got != 0 {
		t.Errorf("cursor = %d, want the clicked row 0", got)
	}
}

func TestClickingFurtherDownSelectsThatRow(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	m.View()
	m.click(5, m.bodyTop+3)
	if m.detail == nil || m.detail.key != "192.0.2.20:22/tcp" {
		t.Fatalf("opened %+v, want the third service", m.detail)
	}
	if got := m.tables[tabServices].Cursor(); got != 2 {
		t.Errorf("cursor = %d, want 2", got)
	}
}

func TestClickingChromeIsIgnored(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	m.View()
	m.click(5, m.bodyTop) // the table's own header row
	if m.detail != nil {
		t.Errorf("the header row opened %+v", m.detail)
	}
	m.click(5, m.height-1) // status line
	if m.detail != nil {
		t.Errorf("the status line opened %+v", m.detail)
	}
}

func TestWheelScrollsTheOpenDetail(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	m.View()
	m.click(5, m.bodyTop+1)
	if m.detail == nil {
		t.Fatal("no detail open")
	}
	m.detail.vp.SetContent(strings.Repeat("line\n", 200))
	before := m.detail.vp.YOffset
	m.handleMouse(tea.MouseMsg{Button: tea.MouseButtonWheelDown})
	if m.detail.vp.YOffset <= before {
		t.Error("wheel down did not scroll the detail view")
	}
}

// ---------------------------------------------------------------------- keyboard

// keyMsg builds the key messages the handlers switch on. Everything that is a
// printable character goes through KeyRunes, exactly as the terminal sends it.
func keyMsg(key string) tea.KeyMsg {
	switch key {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
}

func TestEnterOpensTheSelectedRow(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabHosts
	m.selectRow(1)
	if _, _ = m.handleKey(keyMsg("enter")); m.detail == nil {
		t.Fatal("enter opened nothing")
	}
	if m.detail.kind != "host" || m.detail.key != "192.0.2.30" {
		t.Errorf("opened %+v, want the second host", m.detail)
	}
}

func TestBracketsBrowseRowsInsideTheDetail(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	if _, _ = m.handleKey(keyMsg("enter")); m.detail == nil {
		t.Fatal("enter opened nothing")
	}
	first := m.detail.key
	m.handleKey(keyMsg("]"))
	if m.detail.key == first {
		t.Errorf("] did not move: still %s", m.detail.key)
	}
	if m.detail.key != "192.0.2.10:8096/tcp" {
		t.Errorf("] opened %s, want the next service", m.detail.key)
	}
	m.handleKey(keyMsg("["))
	if m.detail.key != first {
		t.Errorf("[ went to %s, want back to %s", m.detail.key, first)
	}
}

func TestQuitClosesDetailBeforeQuitting(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	m.handleKey(keyMsg("enter"))
	if m.detail == nil {
		t.Fatal("no detail open")
	}
	_, cmd := m.handleKey(keyMsg("q"))
	if m.detail != nil {
		t.Error("q should close the drill-down first")
	}
	if cmd != nil {
		t.Error("q must not quit while a drill-down was open")
	}
	_, cmd = m.handleKey(keyMsg("q"))
	if cmd == nil {
		t.Fatal("second q should quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("second q returned %T, want tea.QuitMsg", cmd())
	}
}

func TestEscapeClosesDetailAndNothingElse(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabFindings
	m.handleKey(keyMsg("enter"))
	_, cmd := m.handleKey(keyMsg("esc"))
	if m.detail != nil || cmd != nil {
		t.Errorf("esc closed=%v cmd=%v, want detail closed and no quit", m.detail != nil, cmd != nil)
	}
	_, cmd = m.handleKey(keyMsg("esc"))
	if cmd == nil {
		t.Error("esc with no detail should quit")
	}
}

func TestSwitchingPagesDropsAStaleDetail(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	m.handleKey(keyMsg("enter"))
	if m.detail == nil {
		t.Fatal("no detail open")
	}
	m.handleKey(keyMsg("tab"))
	if m.detail != nil {
		t.Error("the drill-down survived a page change and now describes the wrong row")
	}
	if m.tab != tabFindings {
		t.Errorf("tab = %d, want findings (the page after services)", m.tab)
	}
}

func TestNumberKeysJumpToAPage(t *testing.T) {
	m := newTestModel(t)
	m.handleKey(keyMsg("4"))
	if m.tab != tabFindings {
		t.Errorf("tab = %d, want findings", m.tab)
	}
	m.handleKey(keyMsg("6"))
	if m.tab != tabReport {
		t.Errorf("tab = %d, want report", m.tab)
	}
	m.handleKey(keyMsg("9")) // out of range: ignore, do not crash
	if m.tab != tabReport {
		t.Errorf("tab = %d after an out-of-range key", m.tab)
	}
}

func TestScrollKeysMoveTheTableCursorNotTheReport(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	m.handleKey(keyMsg("j"))
	if got := m.tables[tabServices].Cursor(); got != 1 {
		t.Errorf("cursor = %d, want 1", got)
	}
	m.handleKey(keyMsg("G"))
	if got := m.tables[tabServices].Cursor(); got != len(m.services)-1 {
		t.Errorf("cursor = %d, want %d", got, len(m.services)-1)
	}
}

func TestDetailScrollsInsteadOfTheTable(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	m.View()
	m.handleKey(keyMsg("enter"))
	m.detail.vp.SetContent(strings.Repeat("row\n", 200))
	cursorBefore := m.tables[tabServices].Cursor()
	m.handleKey(keyMsg("j"))
	if m.detail.vp.YOffset == 0 {
		t.Error("j should scroll the drill-down")
	}
	if m.tables[tabServices].Cursor() != cursorBefore {
		t.Error("j moved the table while the drill-down had the screen")
	}
}

func TestHistoryRowLoadsThatScan(t *testing.T) {
	// A real store behind the model, so this proves the whole path: cursor on a
	// history row, enter, and the engine reloads exactly that run.
	st, err := store.Open(filepath.Join(t.TempDir(), "netwatch.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	for _, started := range []string{"2026-10-24T22:09:33Z", "2026-10-25T12:00:00Z"} {
		r := fixture()
		r.Started = started
		if _, err := st.Save(r); err != nil {
			t.Fatalf("save: %v", err)
		}
	}

	m := newTestModel(t)
	m.engine = scan.New(nil, st)
	history, err := st.History(50)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	m.history = history
	m.rebuild()
	m.tab = tabHistory
	m.selectRow(1)
	_, cmd := m.handleKey(keyMsg("enter"))
	if cmd == nil {
		t.Fatal("enter on a history row should load it")
	}
	if m.detail != nil {
		t.Error("a history row should not open a drill-down")
	}
	msg, ok := cmd().(loadedMsg)
	if !ok {
		t.Fatalf("cmd returned %T, want loadedMsg", cmd())
	}
	if msg.err != nil {
		t.Fatalf("load failed: %v", msg.err)
	}
	if msg.runID != 1 { // the older run, listed second
		t.Errorf("runID = %d, want 1", msg.runID)
	}
	if msg.result == nil || msg.result.Started != "2026-10-24T22:09:33Z" {
		t.Errorf("loaded the wrong scan: %+v", msg.result)
	}
}

func TestScrollingTheReportStillWorks(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabReport
	m.reportVP.SetContent(strings.Repeat("line\n", 200))
	m.handleKey(keyMsg("j"))
	if m.reportVP.YOffset == 0 {
		t.Error("the report viewport did not scroll")
	}
}

// ------------------------------------------------------------------- regression

func TestEnterWorksAfterBootingFromEmpty(t *testing.T) {
	// The live sequence: start with no scan (every table empty), then load one.
	// An empty bubbles table parks its cursor at -1 and a later SetRows does
	// not restore it, so a naive bounds check let Enter index [-1].
	m := New(nil, nil)
	m.width, m.height = 100, 40
	m.rebuild() // no result yet, exactly as Init does
	m.result = fixture()
	m.rebuild()
	m.resize()

	m.tab = tabServices
	if _, _ = m.handleKey(keyMsg("enter")); m.detail == nil {
		t.Fatal("enter opened nothing after booting empty")
	}
	if m.detail.key != "192.0.2.10:51413/tcp" {
		t.Errorf("opened %s, want the first service", m.detail.key)
	}
}

func TestOpeningThenResizingKeepsTheDetailReadable(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabServices
	m.View()
	m.handleKey(keyMsg("enter"))
	if m.detail == nil {
		t.Fatal("no detail open")
	}
	m.width, m.height = 60, 30
	m.resize()
	out := m.detail.vp.View()
	for i, line := range strings.Split(out, "\n") {
		if w := lipgloss.Width(line); w > 60 {
			t.Errorf("after resize line %d is %d wide: %q", i, w, line)
		}
	}
	if !strings.Contains(out, "Transmission") {
		t.Errorf("the resized drill-down lost its subject:\n%s", out)
	}
}
