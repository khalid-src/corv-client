package profile

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Imported is a profile parsed from an external source, together with any
// secrets that came with it. The caller stores Password/Passphrase in the
// vault and the Profile in the registry; this package never touches the vault.
type Imported struct {
	Profile    Profile
	Password   string
	Passphrase string
	// KeyMaterial holds an identity key supplied inline (rather than as a file
	// path). The import flow writes it to a key file and points the profile's
	// IdentityFile at it.
	KeyMaterial string
}

// Import reads connections from a file, choosing the format by extension:
// .csv is parsed as CSV, anything else as an OpenSSH client config. It is the
// single entry point used by the CLI and TUI import flows.
func Import(path string) ([]Imported, error) {
	if strings.EqualFold(filepath.Ext(path), ".csv") {
		return ImportCSV(path)
	}
	profiles, err := ImportSSHConfig(path)
	if err != nil {
		return nil, err
	}
	out := make([]Imported, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, Imported{Profile: p})
	}
	return out, nil
}

// csvAliases maps accepted header names (lower-cased) to a canonical field.
var csvAliases = map[string]string{
	"name": "name", "alias": "name",
	"host": "host", "hostname": "host", "address": "host", "ip": "host",
	"user": "user", "username": "user", "login": "user",
	"port":          "port",
	"identity_file": "key", "identityfile": "key", "key": "key", "key_file": "key", "keyfile": "key", "key_path": "key",
	"key_string": "keydata", "keystring": "keydata", "private_key": "keydata", "privatekey": "keydata",
	"key_data": "keydata", "keydata": "keydata", "public_key": "keydata", "publickey": "keydata", "pem": "keydata",
	"key_type": "keytype", "keytype": "keytype",
	"password": "password", "pass": "password", "pwd": "password",
	"passphrase": "passphrase", "key_passphrase": "passphrase",
	"proxy_jump": "jump", "proxyjump": "jump", "jump": "jump", "bastion": "jump",
}

// ImportCSV parses a connection list from a CSV file. The first row is a
// header; columns may appear in any order and unknown columns are ignored.
// Recognised columns (with common aliases): name, host, user, port,
// identity_file, password, passphrase, proxy_jump. A row needs at least a
// host; the name defaults to the host when omitted.
func ImportCSV(path string) ([]Imported, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // tolerate ragged rows
	r.TrimLeadingSpace = true

	header, err := r.Read()
	if err == io.EOF {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read csv header: %w", err)
	}

	col := map[string]int{}
	for i, h := range header {
		if canon, ok := csvAliases[strings.ToLower(strings.TrimSpace(h))]; ok {
			col[canon] = i
		}
	}
	if _, ok := col["host"]; !ok {
		return nil, fmt.Errorf("csv must have a host column (got: %s)", strings.Join(header, ", "))
	}

	get := func(row []string, key string) string {
		if i, ok := col[key]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}

	var out []Imported
	line := 1
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		line++
		if err != nil {
			return nil, fmt.Errorf("read csv line %d: %w", line, err)
		}

		host := get(row, "host")
		if host == "" {
			continue // skip blank rows
		}
		user := get(row, "user")
		name := get(row, "name")
		if name == "" {
			name = host
		}

		port := 0
		if pt := get(row, "port"); pt != "" {
			p, err := strconv.Atoi(pt)
			if err != nil || p <= 0 || p > 65535 {
				// Skip a malformed row rather than aborting the whole import:
				// the valid rows should still come through.
				continue
			}
			port = p
		}

		target := host
		if user != "" {
			target = user + "@" + host
		}

		identity := expandHome(get(row, "key"))
		keyMaterial := ""
		if identity == "" { // key supplied inline rather than as a path
			keyMaterial = formatKey(get(row, "keytype"), get(row, "keydata"))
		}

		out = append(out, Imported{
			Profile: Profile{
				Name:         name,
				Target:       target,
				Port:         port,
				IdentityFile: identity,
				ProxyJump:    get(row, "jump"),
			},
			Password:    get(row, "password"),
			Passphrase:  get(row, "passphrase"),
			KeyMaterial: keyMaterial,
		})
	}
	return out, nil
}

// formatKey normalises inline key material into a writable key file body. A PEM
// block or an already-prefixed public key ("ssh-ed25519 AAAA...") is kept as is;
// bare base64 is prefixed with its key type when one is given.
func formatKey(keyType, data string) string {
	data = strings.TrimSpace(data)
	if data == "" {
		return ""
	}
	lower := strings.ToLower(data)
	if strings.Contains(data, "BEGIN") || strings.ContainsAny(data, " \t") ||
		strings.HasPrefix(lower, "ssh-") || strings.HasPrefix(lower, "ecdsa-") ||
		strings.HasPrefix(lower, "sk-") {
		return data
	}
	if t := strings.TrimSpace(keyType); t != "" {
		return t + " " + data
	}
	return data
}
