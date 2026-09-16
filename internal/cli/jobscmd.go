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

type jobsClient interface {
	Jobs() ([]broker.RunInfo, error)
}

var newJobsClient = func(self string) jobsClient { return broker.NewClient(self) }

func cmdJobs(args []string, stdout, stderr io.Writer) int {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		err := errors.New("usage: corv jobs [--json]")
		if hasArg(args, "--json") {
			return writeJobsJSON(stdout, nil, "bad_request", err)
		}
		return fail(stderr, err)
	}

	self, err := os.Executable()
	var runs []broker.RunInfo
	if err == nil {
		runs, err = newJobsClient(self).Jobs()
	}
	if err != nil {
		if asJSON {
			return writeJobsJSON(stdout, nil, "local_error", err)
		}
		return fail(stderr, err)
	}
	if runs == nil {
		runs = []broker.RunInfo{}
	}
	if asJSON {
		return writeJobsJSON(stdout, runs, "", nil)
	}
	writeJobsPlain(stdout, runs)
	return 0
}

func writeJobsPlain(w io.Writer, runs []broker.RunInfo) {
	if len(runs) == 0 {
		fmt.Fprintln(w, "no active or retained runs")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN ID\tCONNECTION\tSTATUS\tSTARTED\tEXIT")
	for _, run := range runs {
		exit := "-"
		if run.ExitCode != nil {
			exit = fmt.Sprint(*run.ExitCode)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", run.RunID, run.Connection, run.Status, run.StartedAt.Local().Format("2006-01-02 15:04:05"), exit)
	}
	_ = tw.Flush()
}

func writeJobsJSON(w io.Writer, runs []broker.RunInfo, kind string, err error) int {
	if runs == nil {
		runs = []broker.RunInfo{}
	}
	payload := struct {
		OK        bool             `json:"ok"`
		Runs      []broker.RunInfo `json:"runs"`
		Error     string           `json:"error,omitempty"`
		ErrorKind string           `json:"error_kind,omitempty"`
	}{OK: err == nil, Runs: runs}
	if err != nil {
		payload.Error = err.Error()
		payload.ErrorKind = kind
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
	if err != nil {
		return 1
	}
	return 0
}

func hasArg(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}
