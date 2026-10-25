package report

import (
	"strings"
	"testing"

	"github.com/roks0n/netwatch/internal/model"
)

// OSV writes MODERATE where GitHub writes MEDIUM. When the label is not in the
// order map it used to sort ahead of everything, so a moderate distro advisory
// impersonated the top of the findings list.
func TestSeverityRankOrdersEveryLabelWeSee(t *testing.T) {
	cases := []struct {
		severity string
		want     int
	}{
		{"critical", 0},
		{"CRITICAL", 0},
		{"high", 1},
		{"medium", 2},
		{"MODERATE", 2}, // the same tier under a different vendor's name
		{"low", 3},
		{"info", 4},
		{"unknown", 5},
		{"", 6},             // missing sorts last, not first
		{"trivial", 6},      // unrecognised cannot impersonate the worst
		{"  moderate  ", 2}, // padding from a scraped field is not a new tier
	}
	for _, c := range cases {
		if got := SeverityRank(c.severity); got != c.want {
			t.Errorf("SeverityRank(%q) = %d, want %d", c.severity, got, c.want)
		}
	}

	if SeverityRank("MODERATE") <= SeverityRank("high") {
		t.Error("moderate must not outrank high")
	}
	if SeverityRank("nonsense") <= SeverityRank("critical") {
		t.Error("an unrecognised label must not outrank critical")
	}
}

func TestSortFindingsPutsWorstFirst(t *testing.T) {
	fs := []model.Finding{
		{Kind: "advisory", App: "B", Ref: "2", Severity: "moderate"},
		{Kind: "advisory", App: "A", Ref: "1", Severity: "critical"},
		{Kind: "update", App: "A", Ref: "0", Severity: "info"},
		{Kind: "advisory", App: "C", Ref: "3", Severity: "high"},
		{Kind: "advisory", App: "D", Ref: "4", Severity: "mystery-label"},
	}
	SortFindings(fs)

	var refs []string
	for _, f := range fs {
		refs = append(refs, f.Ref)
	}
	got := strings.Join(refs, ",")
	want := "1,3,2,0,4" // critical, high, moderate, info, unrecognised last
	if got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
}
