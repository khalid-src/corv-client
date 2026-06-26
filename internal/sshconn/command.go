package sshconn

import "strings"

// CommandString renders a command for SSH exec, which delivers a single
// string to the remote user's shell rather than an argv array.
//
// The contract has two cases:
//
//   - A single argument is treated as a remote shell command line and passed
//     through verbatim, matching the familiar `ssh host "cmd"` behaviour
//     (e.g. corv host -- "cd /app && make").
//   - Multiple arguments are an argv whose boundaries are preserved by
//     POSIX-quoting each element, so they cannot be re-split by the remote
//     shell (e.g. corv host -- sh -lc "cd /app && make").
func CommandString(command []string) string {
	if len(command) == 1 {
		return command[0]
	}
	quoted := make([]string, len(command))
	for i, arg := range command {
		quoted[i] = shellQuote(arg)
	}
	return strings.Join(quoted, " ")
}

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if isShellSafe(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
}

func isShellSafe(arg string) bool {
	for _, r := range arg {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune("@%_+=:,./-", r):
		default:
			return false
		}
	}
	return true
}
