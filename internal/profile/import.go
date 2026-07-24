package profile

import (
	"bufio"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/khalid-src/corv-client/internal/paths"
)

// TrimPath cleans a user-entered import path: it trims surrounding whitespace
// and a single pair of matching quotes, so a pasted, quoted path (common when
// copying from a file explorer) works without manual editing.
func TrimPath(p string) string {
	p = strings.TrimSpace(p)
	if len(p) >= 2 {
		first, last := p[0], p[len(p)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return p[1 : len(p)-1] // preserve quoted content verbatim
		}
	}
	return p
}

// WriteIdentityFile persists key material supplied inline during import to a
// private (0600) key file under the Corv home and returns its path. Profile
// names are already filename-safe (see nameRE), so they are used verbatim.
func WriteIdentityFile(name, material string) (string, error) {
	p, err := paths.Default()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(p.Root, "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+".key")
	if !strings.HasSuffix(material, "\n") {
		material += "\n"
	}
	if err := writeFile(path, []byte(material), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// ImportSSHConfig parses an OpenSSH client config file and returns the
// profiles it can derive from concrete Host blocks. Wildcard hosts
// (containing * or ?) and the catch-all "Host *" are skipped because they
// are not connectable targets on their own.
//
// Only the fields Corv uses are read: HostName, User, Port, IdentityFile,
// and ProxyJump. The profile name is the Host alias. A Host line may list
// several aliases; each becomes its own profile sharing the block's
// settings. Include directives are followed recursively.
func ImportSSHConfig(path string) ([]Profile, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".ssh", "config")
	}
	return importSSHConfig(path, map[string]bool{})
}

func importSSHConfig(path string, seen map[string]bool) ([]Profile, error) {
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	if seen[path] {
		return nil, nil
	}
	seen[path] = true

	blocks, err := parseSSHConfig(path, seen)
	if err != nil {
		return nil, err
	}

	var names []string
	seenNames := map[string]bool{}
	for _, b := range blocks {
		for _, alias := range b.aliases {
			if alias != "" && !strings.HasPrefix(alias, "!") && !strings.ContainsAny(alias, "*?") && !seenNames[alias] {
				seenNames[alias] = true
				names = append(names, alias)
			}
		}
	}
	aliases := make(map[string]sshConfigBlock, len(names))
	for _, name := range names {
		aliases[name] = resolveSSHConfig(name, blocks)
	}

	profiles := make([]Profile, 0, len(names))
	for _, alias := range names {
		resolved := aliases[alias]
		host := resolved.hostName
		if host == "" {
			host = alias
		}
		target := host
		if resolved.user != "" {
			target = fmt.Sprintf("%s@%s", resolved.user, host)
		}
		profiles = append(profiles, Profile{
			Name:         alias,
			Target:       target,
			Port:         resolved.port,
			IdentityFile: resolved.identity,
			ProxyJump:    resolveProxyJump(resolved.proxyJump, aliases),
		})
	}
	return profiles, nil
}

func resolveSSHConfig(name string, blocks []sshConfigBlock) sshConfigBlock {
	var resolved sshConfigBlock
	for _, block := range blocks {
		if !hostBlockMatches(name, block.aliases) {
			continue
		}
		if resolved.hostName == "" {
			resolved.hostName = block.hostName
		}
		if resolved.user == "" {
			resolved.user = block.user
		}
		if resolved.port == 0 {
			resolved.port = block.port
		}
		if resolved.identity == "" {
			resolved.identity = block.identity
		}
		if resolved.proxyJump == "" {
			resolved.proxyJump = block.proxyJump
		}
	}
	return resolved
}

func hostBlockMatches(name string, patterns []string) bool {
	name = strings.ToLower(name)
	matched := false
	for _, pattern := range patterns {
		negated := strings.HasPrefix(pattern, "!")
		pattern = strings.TrimPrefix(strings.ToLower(pattern), "!")
		ok, err := pathpkg.Match(pattern, name)
		if err != nil || !ok {
			continue
		}
		if negated {
			return false
		}
		matched = true
	}
	return matched
}

type sshConfigBlock struct {
	aliases   []string
	hostName  string
	user      string
	port      int
	identity  string
	proxyJump string
}

func parseSSHConfig(path string, seen map[string]bool) ([]sshConfigBlock, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var blocks []sshConfigBlock
	var cur *sshConfigBlock

	flush := func() {
		if cur != nil {
			blocks = append(blocks, *cur)
			cur = nil
		}
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value := splitConfigLine(line)
		switch strings.ToLower(key) {
		case "host":
			flush()
			cur = &sshConfigBlock{aliases: strings.Fields(value)}
		case "include":
			flush()
			included, err := parseIncludes(path, value, seen)
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, included...)
		case "hostname":
			if cur != nil && cur.hostName == "" {
				cur.hostName = value
			}
		case "user":
			if cur != nil && cur.user == "" {
				cur.user = value
			}
		case "port":
			if cur != nil && cur.port == 0 {
				if p, err := strconv.Atoi(value); err == nil {
					cur.port = p
				}
			}
		case "identityfile":
			if cur != nil && cur.identity == "" {
				cur.identity = expandHome(value)
			}
		case "proxyjump":
			if cur != nil && cur.proxyJump == "" {
				cur.proxyJump = value
			}
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return blocks, nil
}

func parseIncludes(path, value string, seen map[string]bool) ([]sshConfigBlock, error) {
	var blocks []sshConfigBlock
	for _, pattern := range strings.Fields(value) {
		matches := includeMatches(filepath.Dir(path), pattern)
		for _, match := range matches {
			included, err := parseSSHConfigFile(match, seen)
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, included...)
		}
	}
	return blocks, nil
}

func parseSSHConfigFile(path string, seen map[string]bool) ([]sshConfigBlock, error) {
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	if seen[path] {
		return nil, nil
	}
	seen[path] = true
	return parseSSHConfig(path, seen)
}

func includeMatches(baseDir, pattern string) []string {
	pattern = expandHome(pattern)
	var patterns []string
	if filepath.IsAbs(pattern) {
		patterns = append(patterns, pattern)
	} else {
		patterns = append(patterns, filepath.Join(baseDir, pattern))
		if home, err := os.UserHomeDir(); err == nil {
			patterns = append(patterns, filepath.Join(home, ".ssh", pattern))
		}
	}

	seen := map[string]bool{}
	var matches []string
	for _, p := range patterns {
		globbed, err := filepath.Glob(p)
		if err != nil || len(globbed) == 0 {
			continue
		}
		for _, match := range globbed {
			abs, err := filepath.Abs(match)
			if err == nil {
				match = abs
			}
			if !seen[match] {
				seen[match] = true
				matches = append(matches, match)
			}
		}
	}
	return matches
}

type importJump struct {
	user    string
	host    string
	port    int
	hasPort bool
}

func resolveProxyJump(spec string, aliases map[string]sshConfigBlock) string {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "none") {
		return ""
	}
	parts := strings.Split(spec, ",")
	for i, part := range parts {
		parts[i] = resolveJumpHost(strings.TrimSpace(part), aliases)
	}
	return strings.Join(parts, ",")
}

func resolveJumpHost(spec string, aliases map[string]sshConfigBlock) string {
	jump, ok := parseImportJump(spec)
	if !ok {
		return spec
	}
	block, ok := aliases[jump.host]
	if !ok {
		return spec
	}

	user := jump.user
	if user == "" {
		user = block.user
	}
	host := block.hostName
	if host == "" {
		host = jump.host
	}
	port := jump.port
	if !jump.hasPort {
		port = block.port
	}
	return formatJump(user, host, port)
}

func parseImportJump(spec string) (importJump, bool) {
	if spec == "" {
		return importJump{}, false
	}
	jump := importJump{}
	hostSpec := spec
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		if at == 0 {
			return importJump{}, false
		}
		jump.user = spec[:at]
		hostSpec = spec[at+1:]
	}
	if hostSpec == "" {
		return importJump{}, false
	}
	if strings.HasPrefix(hostSpec, "[") {
		end := strings.Index(hostSpec, "]")
		if end < 0 {
			return importJump{}, false
		}
		jump.host = hostSpec[1:end]
		if jump.host == "" {
			return importJump{}, false
		}
		rest := hostSpec[end+1:]
		if rest == "" {
			return jump, true
		}
		if !strings.HasPrefix(rest, ":") {
			return importJump{}, false
		}
		port, err := strconv.Atoi(rest[1:])
		if err != nil || port <= 0 || port > 65535 {
			return importJump{}, false
		}
		jump.port = port
		jump.hasPort = true
		return jump, true
	}
	if strings.Count(hostSpec, ":") > 1 {
		return importJump{}, false
	}
	if host, portText, hasPort := strings.Cut(hostSpec, ":"); hasPort {
		if host == "" {
			return importJump{}, false
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port <= 0 || port > 65535 {
			return importJump{}, false
		}
		jump.host = host
		jump.port = port
		jump.hasPort = true
		return jump, true
	}
	jump.host = hostSpec
	return jump, true
}

func formatJump(user, host string, port int) string {
	formattedHost := host
	if strings.Contains(host, ":") && !(strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]")) {
		formattedHost = "[" + host + "]"
	}
	if user != "" {
		formattedHost = user + "@" + formattedHost
	}
	if port > 0 {
		formattedHost = formattedHost + ":" + strconv.Itoa(port)
	}
	return formattedHost
}

// splitConfigLine splits an ssh_config line into key and value, tolerating
// both "Key value" and "Key=value" forms.
func splitConfigLine(line string) (string, string) {
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
		val = strings.Trim(val, "\"")
		return key, val
	}
	return line, ""
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
