// Package store keeps scan history and expensive lookups in SQLite.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"

	"github.com/roks0n/netwatch/internal/model"
)

// SCHEMA matches the layout the tool has always used, so an existing database
// written by an earlier version is picked up rather than replaced.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT NOT NULL,
    finished TEXT,
    public_ip TEXT,
    stats TEXT NOT NULL DEFAULT '{}',
    errors TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS hosts (
    run_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    PRIMARY KEY (run_id, ip)
);
CREATE TABLE IF NOT EXISTS services (
    run_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    app TEXT,
    version TEXT,
    product TEXT,
    reach TEXT,
    confidence TEXT,
    evidence TEXT NOT NULL DEFAULT '[]',
    exposures TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (run_id, ip, port, proto)
);
CREATE TABLE IF NOT EXISTS exposures (
    run_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    public INTEGER NOT NULL,
    verified INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    app TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    run_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    app TEXT NOT NULL,
    ref TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'unknown',
    service_key TEXT,
    installed TEXT,
    fixed TEXT,
    url TEXT,
    detail TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_services_run ON services(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
`

// Store is an open SQLite database holding every past scan.
type Store struct {
	db *sql.DB
}

// Open creates the database (and its parent directory) if needed.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// SQLite takes a write lock; one connection keeps the history consistent.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(SCHEMA); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// ------------------------------------------------------------------------ cache

// CacheGet returns a cached value if it is younger than ttl.
func (s *Store) CacheGet(key string, ttl time.Duration) (json.RawMessage, bool) {
	var value, checkedAt string
	err := s.db.QueryRow("SELECT value, checked_at FROM cache WHERE key = ?", key).
		Scan(&value, &checkedAt)
	if err != nil {
		return nil, false
	}
	checked, err := time.Parse(time.RFC3339, checkedAt)
	if err != nil {
		return nil, false
	}
	if time.Since(checked) > ttl {
		return nil, false
	}
	if !json.Valid([]byte(value)) {
		return nil, false
	}
	return json.RawMessage(value), true
}

// CacheSet stores a value until the next scan replaces it.
func (s *Store) CacheSet(key string, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return
	}
	_, _ = s.db.Exec(
		`INSERT INTO cache(key, value, checked_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, checked_at=excluded.checked_at`,
		key, string(encoded), model.UTCNow())
}

// ------------------------------------------------------------------------- runs

// Save persists one scan and returns its run id. The diff against the
// previous run is computed here so every save path records it, and it
// travels inside stats — the layout earlier versions used — so reloaded
// scans keep their "changes since previous scan".
func (s *Store) Save(result *model.ScanResult) (int64, error) {
	if result.Diff == nil {
		if _, err := s.Diff(result); err != nil {
			result.Errors = append(result.Errors, "diff: "+err.Error())
		}
	}
	if result.Diff != nil {
		if result.Stats == nil {
			result.Stats = map[string]any{}
		}
		result.Stats["diff"] = result.Diff
	}
	stats, _ := json.Marshal(result.Stats)
	errors, _ := json.Marshal(result.Errors)

	res, err := s.db.Exec(
		"INSERT INTO runs(started, finished, public_ip, stats, errors) VALUES(?,?,?,?,?)",
		result.Started, nullString(result.Finished), nullString(result.PublicIP),
		string(stats), string(errors))
	if err != nil {
		return 0, err
	}
	runID, _ := res.LastInsertId()

	for _, host := range result.Hosts {
		if _, err := s.db.Exec(
			"INSERT OR REPLACE INTO hosts(run_id, ip, mac, hostname) VALUES(?,?,?,?)",
			runID, host.IP, nullString(host.MAC), nullString(host.Hostname)); err != nil {
			return runID, err
		}
		for _, svc := range host.Services {
			evidence, _ := json.Marshal(svc.Evidence)
			exposures, _ := json.Marshal(svc.Exposures)
			if _, err := s.db.Exec(
				`INSERT INTO services(run_id, ip, port, proto, app, version, product, reach,
				 confidence, evidence, exposures) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
				runID, svc.IP, svc.Port, svc.Proto, svc.App, nullString(svc.Version),
				nullString(svc.Product), string(svc.Reach), nullString(svc.Confidence),
				string(evidence), string(exposures)); err != nil {
				return runID, err
			}
		}
	}

	for _, e := range result.Exposures {
		if _, err := s.db.Exec(
			`INSERT INTO exposures(run_id, kind, target, public, verified, detail, app)
			 VALUES(?,?,?,?,?,?,?)`,
			runID, e.Kind, e.Target, boolToInt(e.Public), boolToInt(e.Verified),
			e.Detail, nullString(e.App)); err != nil {
			return runID, err
		}
	}

	for _, f := range result.Findings {
		if _, err := s.db.Exec(
			`INSERT INTO findings(run_id, kind, app, ref, title, severity, service_key,
			 installed, fixed, url, detail, first_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			runID, f.Kind, f.App, f.Ref, f.Title, f.Severity, nullString(f.ServiceKey),
			nullString(f.Installed), nullString(f.Fixed), nullString(f.URL), f.Detail,
			s.firstSeen(f)); err != nil {
			return runID, err
		}
	}
	return runID, nil
}

// firstSeen keeps the original discovery date of a finding across scans, so the
// TUI can tell a brand-new CVE from one that has been open for weeks.
func (s *Store) firstSeen(f model.Finding) string {
	var first sql.NullString
	err := s.db.QueryRow(
		"SELECT MIN(first_seen) FROM findings WHERE kind=? AND app=? AND ref=?",
		f.Kind, f.App, f.Ref).Scan(&first)
	if err == nil && first.Valid && first.String != "" {
		return first.String
	}
	return model.UTCNow()
}

// LatestRunID is the id of the most recent scan, or 0 when there is none.
func (s *Store) LatestRunID() int64 {
	var id sql.NullInt64
	if err := s.db.QueryRow("SELECT MAX(id) FROM runs").Scan(&id); err != nil {
		return 0
	}
	return id.Int64
}

// Latest reloads the most recent scan from disk.
func (s *Store) Latest() (*model.ScanResult, error) {
	runID := s.LatestRunID()
	if runID == 0 {
		return nil, nil
	}

	var started string
	var finished, publicIP, stats, errors sql.NullString
	err := s.db.QueryRow("SELECT started, finished, public_ip, stats, errors FROM runs WHERE id=?", runID).
		Scan(&started, &finished, &publicIP, &stats, &errors)
	if err != nil {
		return nil, fmt.Errorf("run %d: %w", runID, err)
	}

	result := model.NewScanResult()
	result.Started = started
	result.Finished = finished.String
	result.PublicIP = publicIP.String
	_ = json.Unmarshal([]byte(orEmpty(stats.String, "{}")), &result.Stats)
	_ = json.Unmarshal([]byte(orEmpty(errors.String, "[]")), &result.Errors)
	if raw, ok := result.Stats["diff"]; ok {
		if encoded, err := json.Marshal(raw); err == nil {
			var diff model.Diff
			if json.Unmarshal(encoded, &diff) == nil {
				result.Diff = &diff
			}
		}
		delete(result.Stats, "diff")
	}

	hosts := map[string]*model.Host{}
	order := []string{}
	hostFor := func(ip string) *model.Host {
		if h, ok := hosts[ip]; ok {
			return h
		}
		h := &model.Host{IP: ip, Services: []model.Service{}}
		hosts[ip] = h
		order = append(order, ip)
		return h
	}

	rows, err := s.db.Query("SELECT ip, mac, hostname FROM hosts WHERE run_id=? ORDER BY ip", runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ip string
		var mac, hostname sql.NullString
		if err := rows.Scan(&ip, &mac, &hostname); err != nil {
			rows.Close()
			return nil, err
		}
		h := hostFor(ip)
		h.MAC = mac.String
		h.Hostname = hostname.String
	}
	rows.Close()

	rows, err = s.db.Query(
		"SELECT ip, port, proto, app, version, product, reach, confidence, evidence, exposures "+
			"FROM services WHERE run_id=? ORDER BY ip, port", runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ip, proto string
		var port int
		var app, version, product, reach, confidence, evidence, exposures sql.NullString
		if err := rows.Scan(&ip, &port, &proto, &app, &version, &product, &reach,
			&confidence, &evidence, &exposures); err != nil {
			rows.Close()
			return nil, err
		}
		svc := model.Service{
			IP: ip, Port: port, Proto: proto,
			App:        orDefault(app.String, "unknown"),
			Version:    version.String,
			Product:    product.String,
			Reach:      model.Reach(orDefault(reach.String, string(model.ReachLAN))),
			Confidence: orDefault(confidence.String, "low"),
			Evidence:   []string{},
			Exposures:  []string{},
		}
		_ = json.Unmarshal([]byte(orEmpty(evidence.String, "[]")), &svc.Evidence)
		_ = json.Unmarshal([]byte(orEmpty(exposures.String, "[]")), &svc.Exposures)
		hostFor(ip).Services = append(hostFor(ip).Services, svc)
	}
	rows.Close()

	rows, err = s.db.Query(
		"SELECT kind, target, public, verified, detail, app FROM exposures WHERE run_id=?", runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e model.Exposure
		var app sql.NullString
		var public, verified int
		if err := rows.Scan(&e.Kind, &e.Target, &public, &verified, &e.Detail, &app); err != nil {
			rows.Close()
			return nil, err
		}
		e.Public, e.Verified, e.App = public != 0, verified != 0, app.String
		result.Exposures = append(result.Exposures, e)
	}
	rows.Close()

	rows, err = s.db.Query(
		"SELECT kind, app, ref, title, severity, service_key, installed, fixed, url, detail, first_seen "+
			"FROM findings WHERE run_id=?", runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f model.Finding
		var serviceKey, installed, fixed, url sql.NullString
		if err := rows.Scan(&f.Kind, &f.App, &f.Ref, &f.Title, &f.Severity, &serviceKey,
			&installed, &fixed, &url, &f.Detail, &f.FirstSeen); err != nil {
			rows.Close()
			return nil, err
		}
		f.ServiceKey, f.Installed, f.Fixed, f.URL = serviceKey.String, installed.String,
			fixed.String, url.String
		result.Findings = append(result.Findings, f)
	}
	rows.Close()

	sort.Strings(order)
	for _, ip := range order {
		result.Hosts = append(result.Hosts, *hosts[ip])
	}
	return result, nil
}

// Diff compares a scan against the run before it and records it on the result.
func (s *Store) Diff(result *model.ScanResult) (*model.Diff, error) {
	previous, err := s.Latest()
	if err != nil {
		return nil, err
	}
	if previous == nil {
		diff := &model.Diff{
			Baseline:         true,
			NewServices:      []string{},
			GoneServices:     []string{},
			NewFindings:      []model.FindingRef{},
			ResolvedFindings: []model.FindingRef{},
			ReachChanges:     []model.ReachChange{},
		}
		result.Diff = diff
		return diff, nil
	}

	oldSvc := previous.ServiceByKey()
	newSvc := result.ServiceByKey()
	oldFind := findingSet(previous.Findings)
	newFind := findingSet(result.Findings)

	diff := &model.Diff{
		Baseline:         false,
		PreviousStarted:  previous.Started,
		NewServices:      []string{},
		GoneServices:     []string{},
		NewFindings:      []model.FindingRef{},
		ResolvedFindings: []model.FindingRef{},
		ReachChanges:     []model.ReachChange{},
	}
	for key := range newSvc {
		if _, ok := oldSvc[key]; !ok {
			diff.NewServices = append(diff.NewServices, key)
		}
	}
	for key := range oldSvc {
		if _, ok := newSvc[key]; !ok {
			diff.GoneServices = append(diff.GoneServices, key)
		}
	}
	sort.Strings(diff.NewServices)
	sort.Strings(diff.GoneServices)

	for key, ref := range newFind {
		if _, ok := oldFind[key]; !ok {
			diff.NewFindings = append(diff.NewFindings, ref)
		}
	}
	for key, ref := range oldFind {
		if _, ok := newFind[key]; !ok {
			diff.ResolvedFindings = append(diff.ResolvedFindings, ref)
		}
	}
	sortFindings(diff.NewFindings)
	sortFindings(diff.ResolvedFindings)

	for key := range newSvc {
		old, ok := oldSvc[key]
		if !ok || old.Reach == newSvc[key].Reach {
			continue
		}
		diff.ReachChanges = append(diff.ReachChanges, model.ReachChange{
			Key: key, From: string(old.Reach), To: string(newSvc[key].Reach),
		})
	}
	sort.Slice(diff.ReachChanges, func(i, j int) bool {
		return diff.ReachChanges[i].Key < diff.ReachChanges[j].Key
	})

	result.Diff = diff
	return diff, nil
}

func findingSet(findings []model.Finding) map[string]model.FindingRef {
	out := map[string]model.FindingRef{}
	for _, f := range findings {
		out[f.Identity()] = model.FindingRef{Kind: f.Kind, App: f.App, Ref: f.Ref}
	}
	return out
}

func sortFindings(refs []model.FindingRef) {
	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.App != b.App {
			return a.App < b.App
		}
		return a.Ref < b.Ref
	})
}

// RunSummary is one row of the history tab.
type RunSummary struct {
	ID       int64  `json:"id"`
	Started  string `json:"started"`
	Finished string `json:"finished,omitempty"`
	PublicIP string `json:"public_ip,omitempty"`
	Services int    `json:"services"`
	Public   int    `json:"public"`
	Findings int    `json:"findings"`
}

// History lists recent scans, newest first.
func (s *Store) History(limit int) ([]RunSummary, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT r.id, r.started, r.finished, r.public_ip,
		        (SELECT COUNT(*) FROM services s WHERE s.run_id=r.id),
		        (SELECT COUNT(*) FROM services s WHERE s.run_id=r.id AND s.reach='public'),
		        (SELECT COUNT(*) FROM findings f WHERE f.run_id=r.id)
		 FROM runs r ORDER BY r.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RunSummary
	for rows.Next() {
		var r RunSummary
		var finished, publicIP sql.NullString
		if err := rows.Scan(&r.ID, &r.Started, &finished, &publicIP,
			&r.Services, &r.Public, &r.Findings); err != nil {
			return nil, err
		}
		r.Finished, r.PublicIP = finished.String, publicIP.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// Prune keeps the most recent keep runs and drops older history.
func (s *Store) Prune(keep int) error {
	if keep <= 0 {
		return nil
	}
	_, err := s.db.Exec(`
		DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY id DESC LIMIT ?)`, keep)
	if err != nil {
		return err
	}
	for _, table := range []string{"hosts", "services", "exposures", "findings"} {
		if _, err := s.db.Exec(
			"DELETE FROM " + table + " WHERE run_id NOT IN (SELECT id FROM runs)"); err != nil {
			return err
		}
	}
	return nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
