package certstore

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

// Exit statuses of Run.
const (
	ExitOK       = 0
	ExitFailed   = 1 // the command ran and failed, or refused
	ExitUsage    = 2 // bad arguments, or a confirmation nobody can give
	ExitNotFound = 3 // delete: no certificate for that name
)

// Env is what a service's admin CLI supplies to the shared tls commands.
type Env struct {
	// Program is the CLI's name, used in the commands the output suggests
	// ("smtp-in-admin renew-cert mx.example.com").
	Program string
	// Open opens the inventory with the service's own config. Called only by
	// a command that needs storage, so help works without a config.
	Open func(ctx context.Context) (*Inventory, error)

	Out, Err io.Writer
	// Confirm asks a yes-or-no question and returns the answer. A CLI with a
	// prompt of its own passes it, so every command asks the same way.
	Confirm func(question string) bool
	// Interactive says someone is there to answer Confirm. Without that,
	// delete and clean need --yes rather than waiting on a prompt nobody will
	// answer.
	Interactive bool
}

// Stdio is an Env on the process's standard streams, asking on the terminal.
func Stdio(program string, open func(ctx context.Context) (*Inventory, error)) Env {
	return Env{
		Program: program, Open: open,
		Out: os.Stdout, Err: os.Stderr, Interactive: IsTerminal(os.Stdin),
		Confirm: func(question string) bool { return Ask(os.Stdout, os.Stdin, question) },
	}
}

// IsTerminal reports whether f is a terminal someone can answer a prompt on.
// Not "is a character device": /dev/null is one, and a script run with its
// input from there would be prompted, read end-of-file as "no", and report
// success for a delete it never did.
func IsTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// Ask prints question and reads a yes or no from in; anything but "y" or
// "yes" is no.
func Ask(out io.Writer, in io.Reader, question string) bool {
	fmt.Fprintf(out, "%s [y/N] ", question)
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// Usage is the tls commands' whole help — Help with the Synopsis inside it —
// for a CLI to print as its own.
func Usage(program string) string {
	return describe(program) + "\nUsage:\n" + indent(Synopsis(program)) + "\n" + details
}

// Synopsis is the tls commands' usage lines, for a CLI whose help prints a
// command's usage lines itself.
func Synopsis(program string) string {
	return strings.ReplaceAll(`PROGRAM tls list [--role configured|on-demand|orphan] [--json]
PROGRAM tls delete DOMAIN [--yes] [--force]
PROGRAM tls clean [--dry-run] [--yes]
`, "PROGRAM", program)
}

// Help is Usage without the Synopsis, for the same kind of CLI.
func Help(program string) string {
	return describe(program) + "\n" + details
}

func describe(program string) string {
	return strings.ReplaceAll(`Certificates in shared storage. These read the service's config for the
storage settings and work on storage directly, so they answer with the
service stopped and show every node's certificates, on-demand names included.

  list, ls          every stored certificate: its ROLE (configured, on-demand,
                    or orphan — a name nothing serves any more), expiry, and
                    whether its persistent key (and a staged .next key) exist
  delete, del, rm   remove one certificate; its key stays, so a certificate
                    issued later has the same SPKI. Refuses one that is valid
                    and in use: deleting does not replace it — a running
                    leader writes its copy back on its next maintenance pass.
                    To replace a certificate: PROGRAM renew-cert DOMAIN
  clean             remove every expired or unparseable certificate, which no
                    node can serve anyway
`, "PROGRAM", program)
}

const details = `Flags:
      --role ROLE   list: only certificates with this role
      --json        list: print JSON
  -y, --yes         delete, clean: do not ask (required off a terminal)
      --force       delete: also a valid certificate in use. Useful only with
                    every node stopped: the first leader to start then orders
                    a new one, where a running leader writes its copy back
  -n, --dry-run     clean: show what would go, remove nothing

Exit status: 0 done, 1 failed or refused, 2 usage, 3 no such certificate.
`

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n") + "\n"
}

// Run executes one tls command: args are what follows "tls" on the command
// line. Flags may come after the domain.
func Run(env Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(env.Err, Usage(env.Program))
		return ExitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "ls":
		return runList(env, rest)
	case "delete", "del", "rm":
		return runDelete(env, rest)
	case "clean":
		return runClean(env, rest)
	case "help", "-h", "--help":
		fmt.Fprint(env.Out, Usage(env.Program))
		return ExitOK
	}
	msg := fmt.Sprintf("unknown tls command %q", sub)
	if s := closest(sub, []string{"list", "delete", "clean"}); s != "" {
		msg += fmt.Sprintf(" — did you mean %q?", s)
	}
	return usageErr(env, "%s", msg)
}

func usageErr(env Env, format string, a ...any) int {
	fmt.Fprintf(env.Err, "Error: "+format+"\n", a...)
	fmt.Fprintf(env.Err, "  See: %s tls help\n", env.Program)
	return ExitUsage
}

func newFlags(env Env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are reported through usageErr
	return fs
}

// parse accepts flags before and after positional arguments, so
// "tls delete mx.example.com --yes" means what it says.
func parse(env Env, fs *flag.FlagSet, args []string) ([]string, bool) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			usageErr(env, "tls %s: %v", fs.Name(), err)
			return nil, false
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, true
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func (env Env) open(ctx context.Context) (*Inventory, bool) {
	if env.Open == nil {
		fmt.Fprintln(env.Err, "Error: this service has no certificate storage to manage.")
		return nil, false
	}
	inv, err := env.Open(ctx)
	if err != nil {
		fmt.Fprintf(env.Err, "Error: %v\n", err)
		return nil, false
	}
	return inv, true
}

// confirm is no when the CLI supplied no way to ask.
func (env Env) confirm(question string) bool {
	return env.Confirm != nil && env.Confirm(question)
}

func runList(env Env, args []string) int {
	fs := newFlags(env, "list")
	role := fs.String("role", "", "")
	asJSON := fs.Bool("json", false, "")
	pos, ok := parse(env, fs, args)
	if !ok {
		return ExitUsage
	}
	if len(pos) > 0 {
		return usageErr(env, "tls list takes no arguments (got %q)", pos[0])
	}
	switch Role(*role) {
	case "", RoleConfigured, RoleOnDemand, RoleOrphan:
	default:
		return usageErr(env, "unknown --role %q; one of: configured, on-demand, orphan", *role)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	inv, ok := env.open(ctx)
	if !ok {
		return ExitFailed
	}
	all, err := inv.List(ctx)
	if err != nil {
		fmt.Fprintf(env.Err, "Error: %v\n", err)
		return ExitFailed
	}
	list := []Certificate{}
	for _, c := range all {
		if *role == "" || c.Role == Role(*role) {
			list = append(list, c)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(env.Out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(list); err != nil {
			fmt.Fprintf(env.Err, "Error: %v\n", err)
			return ExitFailed
		}
		return ExitOK
	}
	if len(list) == 0 {
		fmt.Fprintln(env.Out, "No certificates in storage match.")
		return ExitOK
	}

	window := inv.RenewBefore()
	counts := map[Role]int{}
	w := tabwriter.NewWriter(env.Out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tROLE\tALG\tEXPIRES\tDAYS\tSTATUS\tKEY\tSTORED")
	for _, c := range list {
		counts[c.Role]++
		expires, days := "-", "-"
		if !c.NotAfter.IsZero() {
			expires = c.NotAfter.Local().Format("2006-01-02")
			days = fmt.Sprint(int(time.Until(c.NotAfter).Hours() / 24))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.Domain, c.Role, orDash(c.Algorithm), expires, days,
			status(c, window), keyState(c), c.LastModified.Local().Format("2006-01-02 15:04"))
	}
	w.Flush()
	fmt.Fprintf(env.Out, "\n%s: %d configured, %d on-demand, %d orphan.\n",
		plural(len(list), "certificate"), counts[RoleConfigured], counts[RoleOnDemand], counts[RoleOrphan])

	unservable := 0
	for _, c := range list {
		if c.Unservable() != "" {
			unservable++
		}
	}
	if unservable > 0 {
		fmt.Fprintf(env.Out, "%s cannot be served: %s tls clean\n", plural(unservable, "certificate"), env.Program)
	}
	for _, c := range list {
		if c.InUse() && time.Until(c.NotAfter) < window/2 {
			fmt.Fprintf(env.Out, "⚠ %s is past half its renewal window and was not renewed: check the leader's log for \"maintenance issue/renew failed\".\n", c.Domain)
		}
	}
	return ExitOK
}

// status reads a certificate the way an operator asks about it. "renewing" is
// inside the renewal window, where maintenance renews it on its next pass;
// past half the window it has been trying and failing.
func status(c Certificate, window time.Duration) string {
	switch {
	case c.Invalid != "":
		return "✗ invalid"
	case c.Expired:
		return "✗ EXPIRED"
	}
	switch left := time.Until(c.NotAfter); {
	case left < window/2:
		return "⚠ overdue"
	case left < window:
		return "renewing"
	}
	return "✓ ok"
}

func keyState(c Certificate) string {
	switch {
	case c.HasKey && c.HasStagedKey:
		return "yes + .next"
	case c.HasKey:
		return "yes"
	case c.HasStagedKey:
		return ".next only"
	}
	return "no"
}

func runDelete(env Env, args []string) int {
	fs := newFlags(env, "delete")
	var yes, force bool
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&yes, "y", false, "")
	fs.BoolVar(&force, "force", false, "")
	pos, ok := parse(env, fs, args)
	if !ok {
		return ExitUsage
	}
	if len(pos) != 1 {
		return usageErr(env, "tls delete needs exactly one domain")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	inv, ok := env.open(ctx)
	if !ok {
		return ExitFailed
	}
	c, err := inv.Get(ctx, pos[0])
	if errors.Is(err, ErrNotStored) {
		fmt.Fprintf(env.Err, "No certificate for %q in storage.\n", c.Domain)
		names := []string{}
		if all, lerr := inv.List(ctx); lerr == nil {
			for _, s := range all {
				names = append(names, s.Domain)
			}
		}
		if s := closest(c.Domain, names); s != "" {
			fmt.Fprintf(env.Err, "  Did you mean %s?\n", s)
		} else {
			fmt.Fprintf(env.Err, "  See: %s tls list\n", env.Program)
		}
		return ExitNotFound
	}
	if err != nil {
		fmt.Fprintf(env.Err, "Error: %v\n", err)
		return ExitFailed
	}

	fmt.Fprintf(env.Out, "%s  %s  %s  expires %s  key %s\n", c.Domain, c.Role, status(c, inv.RenewBefore()),
		dateOrDash(c.NotAfter), keyState(c))
	if c.InUse() && !force {
		refuseInUse(env, c)
		return ExitFailed
	}
	if !yes {
		if !env.Interactive {
			fmt.Fprintln(env.Err, "Refusing to delete without confirmation: not a terminal. Pass --yes.")
			return ExitUsage
		}
		if !env.confirm(fmt.Sprintf("Delete the certificate for %s from shared storage?", c.Domain)) {
			fmt.Fprintln(env.Out, "Nothing done.")
			return ExitOK
		}
	}

	removed, err := inv.Delete(ctx, c.Domain, force)
	if errors.Is(err, ErrInUse) {
		// Renewed between the look above and the delete.
		refuseInUse(env, removed)
		return ExitFailed
	}
	if err != nil {
		fmt.Fprintf(env.Err, "Error: %v\n", err)
		return ExitFailed
	}
	fmt.Fprintf(env.Out, "✓ Deleted %s. Its key stays, so a certificate issued later keeps the same SPKI.\n", removed.Key)
	if removed.InUse() {
		fmt.Fprintf(env.Out, "⚠ It was in use. A running leader writes its copy back on its next maintenance pass.\n  To replace it instead: %s renew-cert %s\n", env.Program, removed.Domain)
	}
	return ExitOK
}

func refuseInUse(env Env, c Certificate) {
	fmt.Fprintf(env.Err, `
✗ Not deleting %s: it is valid and in use (%s).
  Deleting would not replace it. The leader serves it from memory and writes
  it back to storage on its next maintenance pass.
  To replace it:    %s renew-cert %s
  To delete anyway: add --force (see '%s tls help' for when that helps)
`, c.Domain, c.Role, env.Program, c.Domain, env.Program)
}

func runClean(env Env, args []string) int {
	fs := newFlags(env, "clean")
	var yes, dry bool
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&yes, "y", false, "")
	fs.BoolVar(&dry, "dry-run", false, "")
	fs.BoolVar(&dry, "n", false, "")
	pos, ok := parse(env, fs, args)
	if !ok {
		return ExitUsage
	}
	if len(pos) > 0 {
		return usageErr(env, "tls clean takes no arguments (got %q); to remove one certificate: %s tls delete %s", pos[0], env.Program, pos[0])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	inv, ok := env.open(ctx)
	if !ok {
		return ExitFailed
	}
	all, err := inv.List(ctx)
	if err != nil {
		fmt.Fprintf(env.Err, "Error: %v\n", err)
		return ExitFailed
	}
	var doomed []Certificate
	for _, c := range all {
		if c.Unservable() != "" {
			doomed = append(doomed, c)
		}
	}
	if len(doomed) == 0 {
		fmt.Fprintf(env.Out, "Nothing to clean: every certificate in storage (%d) can be served.\n", len(all))
		return ExitOK
	}

	w := tabwriter.NewWriter(env.Out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tROLE\tWHY")
	for _, c := range doomed {
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.Domain, c.Role, c.Unservable())
	}
	w.Flush()
	if dry {
		fmt.Fprintf(env.Out, "\nDry run: would delete %s.\n", plural(len(doomed), "certificate"))
		return ExitOK
	}
	if !yes {
		if !env.Interactive {
			fmt.Fprintln(env.Err, "\nRefusing to delete without confirmation: not a terminal. Pass --yes.")
			return ExitUsage
		}
		if !env.confirm(fmt.Sprintf("\nDelete these %d from shared storage?", len(doomed))) {
			fmt.Fprintln(env.Out, "Nothing done.")
			return ExitOK
		}
	}

	deleted, failed := 0, 0
	var unserved []string
	for _, c := range doomed {
		// Never forced: Delete re-reads, so a chain renewed since the listing
		// is kept rather than removed on the strength of a stale look.
		removed, err := inv.Delete(ctx, c.Domain, false)
		switch {
		case errors.Is(err, ErrInUse):
			fmt.Fprintf(env.Out, "  kept %s: renewed since it was listed\n", c.Domain)
		case errors.Is(err, ErrNotStored):
			// Gone already; nothing to do.
		case err != nil:
			fmt.Fprintf(env.Err, "✗ %s: %v\n", c.Domain, err)
			failed++
		default:
			deleted++
			if removed.Role == RoleConfigured {
				unserved = append(unserved, removed.Domain)
			}
		}
	}
	fmt.Fprintf(env.Out, "✓ Deleted %d of %d. Keys were kept.\n", deleted, len(doomed))
	for _, d := range unserved {
		fmt.Fprintf(env.Out, "⚠ %s is configured and has no usable certificate: %s renew-cert %s\n", d, env.Program, d)
	}
	if failed > 0 {
		return ExitFailed
	}
	return ExitOK
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func dateOrDash(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02")
}

// closest suggests the candidate nearest a mistyped name, or "" when none is
// near enough to be a typo rather than a different name.
func closest(s string, candidates []string) string {
	best, bestDist := "", len(s)/3+1
	for _, c := range candidates {
		if d := distance(s, c); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

// distance is the edit distance counting an adjacent swap as one edit (the
// optimal-string-alignment form): "lsit" is one slip from "list", not two.
func distance(a, b string) int {
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(a)][len(b)]
}
