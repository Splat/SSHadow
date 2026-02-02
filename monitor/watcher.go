package monitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"time"
)

// LogWatcher watches sshd logs and sends parsed events
type LogWatcher struct {
	source  string // file path or "journald"
	tracker *Tracker
	events  chan *LogEvent
}

// NewLogWatcher creates a new log watcher
func NewLogWatcher(source string, tracker *Tracker) *LogWatcher {
	return &LogWatcher{
		source:  source,
		tracker: tracker,
		events:  make(chan *LogEvent, 100),
	}
}

// Watch starts watching the log source
func (w *LogWatcher) Watch(ctx context.Context) error {
	if w.source == "journald" {
		return w.watchJournald(ctx)
	}
	return w.watchFile(ctx)
}

// watchFile tails a log file
func (w *LogWatcher) watchFile(ctx context.Context) error {
	file, err := os.Open(w.source)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// Seek to end of file (only watch new entries)
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("failed to seek to end: %w", err)
	}

	reader := bufio.NewReader(file)

	log.Printf("Watching log file: %s", w.source)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// No new data, wait a bit
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("error reading log: %w", err)
		}

		if line == "" {
			continue
		}

		event := ParseLogLine(line)
		w.processEvent(event)
	}
}

// watchJournald uses journalctl to follow sshd logs
func (w *LogWatcher) watchJournald(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "journalctl",
		"-u", "sshd", // or "ssh" on some systems
		"-f",         // follow
		"-n", "0",    // no historical entries
		"--no-pager",
		"-o", "short-iso",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		// Try alternative service name
		cmd = exec.CommandContext(ctx, "journalctl",
			"-u", "ssh",
			"-f",
			"-n", "0",
			"--no-pager",
			"-o", "short-iso",
		)
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdout pipe: %w", err)
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start journalctl: %w", err)
		}
	}

	log.Printf("Watching journald for sshd events")

	reader := bufio.NewReader(stdout)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("error reading journald: %w", err)
		}

		if line == "" {
			continue
		}

		event := ParseLogLine(line)
		w.processEvent(event)
	}

	return cmd.Wait()
}

// processEvent handles a parsed log event
func (w *LogWatcher) processEvent(event *LogEvent) {
	if event.EventType == EventUnknown {
		return
	}

	switch event.EventType {
	case EventAccepted:
		connID := fmt.Sprintf("%s:%d-%s-%d", event.SourceIP, event.Port, event.Username, event.PID)

		// Create a connection info for the tracker
		w.tracker.AddConnectionFromLog(connID, event)

		log.Printf("Auth: %s@%s (auth: %s, key: %s)",
			event.Username, event.SourceIP, event.AuthType, event.CertID)

	case EventDisconnected, EventSessionClosed:
		// Try to find and remove the connection
		w.tracker.RemoveConnectionByUser(event.Username, event.SourceIP, event.Port)
		log.Printf("Disconnect: %s@%s", event.Username, event.SourceIP)

	case EventFailed:
		log.Printf("Failed auth: %s@%s (auth: %s)", event.Username, event.SourceIP, event.AuthType)
		// Could track failed attempts in the future

	case EventInvalidUser:
		log.Printf("Invalid user: %s from %s", event.Username, event.SourceIP)
	}
}

// Events returns the event channel for external consumers
func (w *LogWatcher) Events() <-chan *LogEvent {
	return w.events
}
