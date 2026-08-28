package rule

import (
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestCanonicalPathCollapsesTraversalForFileEvents(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.protect_rule_file",
		Severity: model.SeverityHigh,
		Expr:     `event.event_type in ["file.write", "file.delete"] && canonical_path(event.file_path) == "/etc/numbat/rules/protect_numbat.yaml"`,
	})
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"plain", "/etc/numbat/rules/protect_numbat.yaml", true},
		{"dot_segment", "/etc/numbat/./rules/protect_numbat.yaml", true},
		{"shallow_traversal", "/etc/numbat/rules/x/../protect_numbat.yaml", true},
		{"deep_traversal_depth4", "/etc/numbat/rules/d0/d1/d2/d3/../../../../protect_numbat.yaml", true},
		{"proc_root_prefix", "/proc/self/root/etc/numbat/rules/protect_numbat.yaml", true},
		{"proc_root_pid_traversal", "/proc/4321/root/etc/numbat/rules/d0/d1/../../protect_numbat.yaml", true},
		{"duplicate_slash", "/etc/numbat//rules/protect_numbat.yaml", true},
		{"unprotected_sibling", "/etc/numbat/rules.example/protect_numbat.yaml", false},
		{"escapes_out", "/etc/numbat/rules/../ordinary.txt", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{EventID: "e", EventType: model.EventFileWrite, FilePath: tc.path}
			matches, err := eng.Eval(ev)
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			got := len(matches) == 1
			if got != tc.want {
				t.Fatalf("path %q: matched=%v want=%v", tc.path, got, tc.want)
			}
		})
	}
}

func TestCanonicalPathCollapsesTraversalForShellArgv(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.protect_rule_rm",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr:     `event.event_type == "command.exec" && shell_commands.exists(command, command.name in ["rm", "unlink"] && command.argv.exists(a, canonical_path(a) == "/usr/local/bin/numbat"))`,
	})
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"plain", "rm -f /usr/local/bin/numbat", true},
		{"deep_traversal_depth5", "rm -f /usr/local/bin/d0/d1/d2/d3/d4/../../../../../numbat", true},
		{"proc_root", "rm -f /proc/self/root/usr/local/bin/numbat", true},
		{"benign_other", "rm -f /tmp/numbat", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{EventID: "e", EventType: model.EventCommandExec, Command: tc.command}
			matches, err := eng.Eval(ev)
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			got := len(matches) == 1
			if got != tc.want {
				t.Fatalf("command %q: matched=%v want=%v", tc.command, got, tc.want)
			}
		})
	}
}

func TestCanonicalizePathUnit(t *testing.T) {
	cases := map[string]string{
		"/etc/numbat/rules/d0/d1/d2/d3/../../../../protect_numbat.yaml": "/etc/numbat/rules/protect_numbat.yaml",
		"/proc/self/root/etc/numbat/rules/x.yaml":                       "/etc/numbat/rules/x.yaml",
		"/proc/thread-self/root/usr/local/bin/numbat":                   "/usr/local/bin/numbat",
		"/proc/12/root/../root/usr/local/bin/numbat":                    "/usr/local/bin/numbat",
		"/usr/local/bin//numbat":                                        "/usr/local/bin/numbat",
		"":                                                              "",
		"/proc/self/root":                                               "/",
	}
	for in, want := range cases {
		if got := model.CanonicalizePath(in); got != want {
			t.Fatalf("CanonicalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}
