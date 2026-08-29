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
		{"proc_root_parent_traversal", "/proc/self/root/../etc/numbat/rules/protect_numbat.yaml", true},
		{"proc_root_dot_prefix", "/proc/./self/root/etc/numbat/rules/protect_numbat.yaml", true},
		{"duplicate_slash", "/etc/numbat//rules/protect_numbat.yaml", true},
		{"windows_separators", `\etc\numbat\rules\protect_numbat.yaml`, true},
		{"different_proc_entry", "/proc/not-a-pid/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"similar_proc_entry", "/proc/self/rooted/etc/numbat/rules/protect_numbat.yaml", false},
		{"unprotected_sibling", "/etc/numbat/rules.example/protect_numbat.yaml", false},
		{"escapes_out", "/etc/numbat/rules/../ordinary.txt", false},
		{"whitespace_is_path_content", " /etc/numbat/rules/protect_numbat.yaml ", false},
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

func TestCanonicalPathKeepsMissingPathEmpty(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.empty_path",
		Severity: model.SeverityLow,
		Expr:     `canonical_path(event.file_path) == ""`,
	})
	matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
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
		{"proc_root", "rm -f /proc/thread-self/root/usr/local/bin/numbat", true},
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
