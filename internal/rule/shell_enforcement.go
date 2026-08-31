package rule

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func posixEnforcementShapeSafe(file *syntax.File) bool {
	return file != nil && posixStatementListEnforcementSafe(file.Stmts)
}

func posixStatementListEnforcementSafe(statements []*syntax.Stmt) bool {
	if len(statements) == 0 {
		return false
	}
	for _, statement := range statements {
		if !posixStatementEnforcementSafe(statement) {
			return false
		}
	}
	return true
}

func posixStatementEnforcementSafe(stmt *syntax.Stmt) bool {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Hdoc != nil {
			return false
		}
		if redirect.Word != nil {
			if _, static := staticWord(redirect.Word); !static {
				return false
			}
		}
		if redirect.N != nil && strings.Trim(redirect.N.Value, "0123456789") != "" {
			return false
		}
	}
	switch command := stmt.Cmd.(type) {
	case nil:
		return len(stmt.Redirs) > 0
	case *syntax.CallExpr:
		return true
	case *syntax.BinaryCmd:
		switch command.Op {
		case syntax.Pipe, syntax.PipeAll:
		case syntax.AndStmt:
			if success, known := posixStaticSuccess(command.X); known && !success {
				return false
			}
		case syntax.OrStmt:
			if success, known := posixStaticSuccess(command.X); known && success {
				return false
			}
		default:
			return false
		}
		return posixStatementEnforcementSafe(command.X) &&
			posixStatementEnforcementSafe(command.Y)
	case *syntax.Subshell:
		return posixStatementListEnforcementSafe(command.Stmts)
	case *syntax.Block:
		return posixStatementListEnforcementSafe(command.Stmts)
	default:
		return false
	}
}

// posixStaticSuccess recognizes only shell builtins whose status cannot depend
// on arguments or the environment. It is used to keep statically unreachable
// short-circuit branches detection-only; unknown statuses remain eligible
// because either branch may execute at runtime.
func posixStaticSuccess(stmt *syntax.Stmt) (bool, bool) {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false, false
	}
	success, known := posixCommandStaticSuccess(stmt.Cmd)
	if !known || len(stmt.Redirs) > 0 && success {
		return false, false
	}
	return success, true
}

func posixCommandStaticSuccess(command syntax.Command) (bool, bool) {
	switch command := command.(type) {
	case *syntax.CallExpr:
		if len(command.Args) == 0 || len(command.Assigns) > 0 {
			return false, false
		}
		name, ok := staticWord(command.Args[0])
		if !ok || name != commandProgram(name) {
			return false, false
		}
		switch name {
		case ":", "true":
			return true, true
		case "false":
			return false, true
		default:
			return false, false
		}
	case *syntax.BinaryCmd:
		left, leftKnown := posixStaticSuccess(command.X)
		switch command.Op {
		case syntax.AndStmt:
			if leftKnown && !left {
				return false, true
			}
			right, rightKnown := posixStaticSuccess(command.Y)
			if leftKnown && left {
				return right, rightKnown
			}
			if rightKnown && !right {
				return false, true
			}
			return false, false
		case syntax.OrStmt:
			if leftKnown && left {
				return true, true
			}
			right, rightKnown := posixStaticSuccess(command.Y)
			if leftKnown && !left {
				return right, rightKnown
			}
			if rightKnown && right {
				return true, true
			}
			return false, false
		default:
			return false, false
		}
	case *syntax.Subshell:
		return posixStaticListSuccess(command.Stmts)
	case *syntax.Block:
		return posixStaticListSuccess(command.Stmts)
	default:
		return false, false
	}
}

func posixStaticListSuccess(statements []*syntax.Stmt) (bool, bool) {
	if len(statements) == 0 {
		return false, false
	}
	return posixStaticSuccess(statements[len(statements)-1])
}

func powerShellEnforcementShapeSafe(source string) bool {
	var singleQuoted, doubleQuoted bool
	for i := 0; i < len(source); i++ {
		switch {
		case singleQuoted:
			if source[i] == '\'' {
				if i+1 < len(source) && source[i+1] == '\'' {
					i++
				} else {
					singleQuoted = false
				}
			}
		case doubleQuoted:
			switch source[i] {
			case '`':
				return false
			case '"':
				doubleQuoted = false
			}
		default:
			switch source[i] {
			case '\'':
				singleQuoted = true
			case '"':
				doubleQuoted = true
			case '&':
				if !cmdRedirectAmpersand(source, i) {
					return false
				}
			case '`', ';', ',', '\n', '\r', '|', '(', ')', '{', '}', '[', ']':
				return false
			}
		}
	}
	return !singleQuoted && !doubleQuoted
}

func cmdEnforcementShapeSafe(source string) bool {
	source = trimCMDEchoPrefix(source)
	var quoted bool
	for i := 0; i < len(source); i++ {
		switch source[i] {
		case '^':
			return false
		case '"':
			quoted = !quoted
		case '&':
			if !quoted && !cmdRedirectAmpersand(source, i) {
				return false
			}
		case '|', '(', ')', '\n', '\r':
			if !quoted {
				return false
			}
		}
	}
	if quoted {
		return false
	}
	words := cmdWords(source)
	if len(words) == 0 {
		return false
	}
	switch commandProgram(strings.ToLower(words[0].text)) {
	case "call", "else", "endlocal", "exit", "for", "goto", "if", "set",
		"setlocal", "start":
		return false
	default:
		return true
	}
}
