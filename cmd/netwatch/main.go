// Command netwatch scans the local network, verifies what the internet can
// reach, and tracks CVEs and new releases for the services it finds.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/roks0n/netwatch/internal/config"
	"github.com/roks0n/netwatch/internal/model"
	"github.com/roks0n/netwatch/internal/report"
	"github.com/roks0n/netwatch/internal/scan"
	"github.com/roks0n/netwatch/internal/store"
	"github.com/roks0n/netwatch/internal/tui"
	"github.com/roks0n/netwatch/internal/vulndb"
)

// Version is stamped at build time.
var Version = "0.1.0"

const usage = `netwatch %s — network exposure scanner

Usage:
  netwatch                 interactive TUI
  netwatch tui             interactive TUI
  netwatch scan            run a scan and print a summary
  netwatch report          render the latest scan as Markdown or JSON
  netwatch findings        list findings from the latest scan
  netwatch init            write a default config file
  netwatch catalog         list known app/version sources

Run "netwatch <command> -h" for per-command flags.
`

func main() {
	args := os.Args[1:]

	// A leading --config belongs to the parent command.
	configPath := ""
	if len(args) >= 2 && args[0] == "--config" {
		configPath, args = args[1], args[2:]
	}

	command := "tui"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}

	switch command {
	case "tui":
		os.Exit(runTUI(configPath))
	case "scan":
		os.Exit(runScan(configPath, args))
	case "report":
		os.Exit(runReport(configPath, args))
	case "findings":
		os.Exit(runFindings(configPath, args))
	case "init":
		os.Exit(runInit(configPath, args))
	case "catalog":
		runCatalog()
	case "version", "--version":
		fmt.Println("netwatch", Version)
	case "help", "-h", "--help":
		fmt.Printf(usage, Version)
	default:
		fmt.Fprintf(os.Stderr, "netwatch: unknown command %q\n\n", command)
		fmt.Printf(usage, Version)
		os.Exit(1)
	}
}

func loadConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netwatch:", err)
		os.Exit(1)
	}
	return cfg
}

func openStore(cfg *config.Config) *store.Store {
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "netwatch: database:", err)
		os.Exit(1)
	}
	return st
}

// interruptedContext cancels on SIGINT so a half-finished scan still saves.
func interruptedContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx, func() { stop() }
}

// -------------------------------------------------------------------- tui

func runTUI(configPath string) int {
	cfg := loadConfig(configPath)
	st := openStore(cfg)
	defer st.Close()
	if err := tui.Run(cfg, scan.New(cfg, st)); err != nil {
		fmt.Fprintln(os.Stderr, "netwatch:", err)
		return 1
	}
	return 0
}

// -------------------------------------------------------------------- scan

func runScan(configPath string, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	full := fs.Bool("full", false, "scan all 65535 TCP ports")
	noExternal := fs.Bool("no-external", false, "skip external verification")
	noVulns := fs.Bool("no-vulns", false, "skip OSV/GitHub checks")
	asJSON := fs.Bool("json", false, "machine-readable output")
	quiet := fs.Bool("quiet", false, "suppress progress output")
	noSave := fs.Bool("no-save", false, "do not record the scan in the database")
	failPublic := fs.Bool("fail-on-public", false, "exit 2 if anything is public")
	failFindings := fs.Bool("fail-on-findings", false, "exit 3 if findings exist")
	_ = fs.Parse(args)

	cfg := loadConfig(configPath)
	st := openStore(cfg)
	defer st.Close()
	engine := scan.New(cfg, st)

	var progress scan.Progress
	if !*asJSON && !*quiet {
		progress = func(pct int, msg string) { fmt.Printf("%3d%% %s\n", pct, msg) }
	}

	ctx, cancel := interruptedContext()
	defer cancel()
	result := engine.Scan(ctx, scan.Options{
		Full:       *full,
		NoExternal: *noExternal,
		NoVulns:    *noVulns,
		NoSave:     *noSave,
	}, progress)

	switch {
	case *asJSON:
		data, err := report.ToJSON(result)
		if err != nil {
			fmt.Fprintln(os.Stderr, "netwatch:", err)
			return 1
		}
		fmt.Println(string(data))
	case !*quiet:
		printSummary(result)
	}

	if *failPublic && len(result.PublicExposures()) > 0 {
		return 2
	}
	if *failFindings && len(result.Findings) > 0 {
		return 3
	}
	return 0
}

func printSummary(result *model.ScanResult) {
	fmt.Println()
	fmt.Println("netwatch scan summary")
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  Public IP\t"+orDash(result.PublicIP))
	fmt.Fprintf(w, "  Hosts\t%d\n", len(result.Hosts))
	fmt.Fprintf(w, "  Services\t%d\n", len(result.Services()))
	fmt.Fprintf(w, "  Public exposures\t%d\n", len(result.PublicExposures()))
	fmt.Fprintf(w, "  Findings\t%d\n", len(result.Findings))
	fmt.Fprintf(w, "  Duration\t%vs\n", result.Stats["duration_s"])
	w.Flush()

	if public := result.PublicExposures(); len(public) > 0 {
		fmt.Println("\nPublic exposure")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  Target\tKind\tApp\tDetail")
		for _, e := range public {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", e.Target, e.Kind, orDash(e.App), clip(e.Detail, 80))
		}
		w.Flush()
	}

	if len(result.Findings) > 0 {
		findings := append([]model.Finding(nil), result.Findings...)
		report.SortFindings(findings)
		fmt.Println("\nFindings")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  Severity\tKind\tApp\tRef\tTitle")
		for _, f := range findings {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", f.Severity, f.Kind, f.App, f.Ref, clip(f.Title, 70))
		}
		w.Flush()
	}

	if len(result.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, e := range result.Errors {
			fmt.Println("  " + e)
		}
	}
	fmt.Println()
}

// ------------------------------------------------------------------ report

func runReport(configPath string, args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	format := fs.String("format", "md", "md or json")
	output := fs.String("o", "", "write to a file")
	fs.StringVar(output, "output", "", "write to a file")
	_ = fs.Parse(args)

	cfg := loadConfig(configPath)
	st := openStore(cfg)
	defer st.Close()

	result, err := st.Latest()
	if err != nil {
		fmt.Fprintln(os.Stderr, "netwatch:", err)
		return 1
	}
	if result == nil {
		fmt.Println("No scans recorded yet. Run `netwatch scan` first.")
		return 1
	}

	if *output != "" {
		path, err := report.Write(result, "", *format, *output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "netwatch:", err)
			return 1
		}
		fmt.Println("Wrote", path)
		return 0
	}
	if *format == "json" {
		data, err := report.ToJSON(result)
		if err != nil {
			fmt.Fprintln(os.Stderr, "netwatch:", err)
			return 1
		}
		fmt.Println(string(data))
		return 0
	}
	fmt.Println(report.ToMarkdown(result))
	return 0
}

// ---------------------------------------------------------------- findings

func runFindings(configPath string, args []string) int {
	fs := flag.NewFlagSet("findings", flag.ExitOnError)
	_ = fs.Parse(args)

	cfg := loadConfig(configPath)
	st := openStore(cfg)
	defer st.Close()

	result, err := st.Latest()
	if err != nil {
		fmt.Fprintln(os.Stderr, "netwatch:", err)
		return 1
	}
	if result == nil || len(result.Findings) == 0 {
		fmt.Println("No findings recorded.")
		return 0
	}

	findings := append([]model.Finding(nil), result.Findings...)
	report.SortFindings(findings)

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  Severity\tKind\tApp\tRef\tInstalled\tFixed\tTitle")
	for _, f := range findings {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Severity, f.Kind, f.App, f.Ref, orDash(f.Installed), orDash(f.Fixed), f.Title)
	}
	w.Flush()
	return 0
}

// -------------------------------------------------------------------- init

func runInit(configPath string, args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	_ = fs.Parse(args)

	path, err := config.WriteDefault(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netwatch:", err)
		return 1
	}
	fmt.Println("Config ready at", path)
	return 0
}

// ----------------------------------------------------------------- catalog

func runCatalog() {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  App\tGitHub repo\tOSV package")
	for _, info := range vulndb.AllApps() {
		fmt.Fprintf(w, "  %s\t%s\t%s\n", info.Name, orDash(info.Repo), orDash(info.OSV))
	}
	w.Flush()
}

// ------------------------------------------------------------------- utils

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
