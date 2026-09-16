package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/khalid-src/corv-client/internal/broker"
)

type statusClient interface {
	Status() (bool, []broker.StatusInfo, error)
}

var newStatusClient = func(self string) statusClient { return broker.NewClient(self) }

var newDoctorClient = func(self string) statusClient { return broker.NewClient(self) }

type statusConnection struct {
	Name        string `json:"name"`
	Target      string `json:"target,omitempty"`
	IdleSeconds int64  `json:"idle_seconds"`
	RunningJobs int    `json:"running_jobs"`
}

type statusResult struct {
	BrokerRunning bool               `json:"broker_running"`
	Connections   []statusConnection `json:"connections"`
	Error         string             `json:"error,omitempty"`
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	full := false
	for _, arg := range args {
		switch arg {
		case "--json":
			asJSON = true
		case "--full":
			full = true
		}
	}
	if len(args) > 2 || containsUnknownStatusArg(args) {
		if asJSON {
			return writeStatusJSON(stdout, statusResult{Connections: []statusConnection{}, Error: "usage: corv status [--json] [--full]"})
		}
		return fail(stderr, errors.New("usage: corv status [--json] [--full]"))
	}

	self, _ := os.Executable()
	running, held, err := newStatusClient(self).Status()
	if err != nil {
		if asJSON {
			return writeStatusJSON(stdout, statusResult{BrokerRunning: running, Connections: []statusConnection{}, Error: err.Error()})
		}
		return fail(stderr, err)
	}
	result := statusResult{BrokerRunning: running, Connections: make([]statusConnection, 0, len(held))}
	for _, info := range held {
		connection := statusConnection{Name: info.Name, IdleSeconds: info.IdleMS / 1000, RunningJobs: info.RunningJobs}
		if full {
			connection.Target = info.Target
		}
		result.Connections = append(result.Connections, connection)
	}
	if asJSON {
		return writeStatusJSON(stdout, result)
	}
	writeStatusPlain(stdout, result)
	return 0
}

func containsUnknownStatusArg(args []string) bool {
	seen := map[string]bool{}
	for _, arg := range args {
		if arg != "--json" && arg != "--full" || seen[arg] {
			return true
		}
		seen[arg] = true
	}
	return false
}

func writeStatusPlain(w io.Writer, result statusResult) {
	if !result.BrokerRunning {
		fmt.Fprintln(w, "no warm connections (broker not running)")
		return
	}
	if len(result.Connections) == 0 {
		fmt.Fprintln(w, "no warm connections")
	} else {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		if result.Connections[0].Target == "" {
			fmt.Fprintln(tw, "NAME\tIDLE\tRUNS")
			for _, info := range result.Connections {
				fmt.Fprintf(tw, "%s\t%ds\t%d\n", info.Name, info.IdleSeconds, info.RunningJobs)
			}
		} else {
			fmt.Fprintln(tw, "NAME\tTARGET\tIDLE\tRUNS")
			for _, info := range result.Connections {
				fmt.Fprintf(tw, "%s\t%s\t%ds\t%d\n", info.Name, info.Target, info.IdleSeconds, info.RunningJobs)
			}
		}
		_ = tw.Flush()
	}
	if result.BrokerRunning {
		fmt.Fprintln(w, "The broker exits automatically after it is idle and no run is active.")
	}
}

func writeStatusJSON(w io.Writer, result statusResult) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
	if result.Error != "" {
		return 1
	}
	return 0
}
