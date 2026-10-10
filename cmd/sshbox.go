package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/term"

	"sshbox"
)

func main() {
	var host string
	var verbose bool
	var noUI bool

	flag.StringVar(&host, "host", "0.0.0.0", "Host/interface to listen on (default: 0.0.0.0)")
	flag.BoolVar(&verbose, "v", false, "Log executed commands and detailed activity (default: disabled)")
	flag.BoolVar(&verbose, "verbose", false, "Log executed commands and detailed activity (default: disabled)")
	flag.BoolVar(&noUI, "no-ui", false, "Disable TUI monitoring and use plain logs (default: false)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <dir> [dir...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	dirs := flag.Args()
	if len(dirs) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	var absDirs []string
	seen := make(map[string]bool)
	for _, d := range dirs {
		abs, err := filepath.Abs(d)
		if err != nil {
			log.Fatalf("Failed to resolve path %s: %v", d, err)
		}
		if !seen[abs] {
			seen[abs] = true
			absDirs = append(absDirs, abs)
		}
	}

	// Validate port conflicts across all jail configs
	conflicts, err := sshbox.CheckPortConflicts(absDirs)
	if err != nil {
		log.Fatalf("Failed to load jail configs: %v", err)
	}
	if len(conflicts) > 0 {
		for _, c := range conflicts {
			fmt.Fprintf(os.Stderr, "Port conflict: %s\n", c.Error())
		}
		os.Exit(1)
	}

	useUI := !noUI && term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd()))

	var mon sshbox.Monitor
	var tui *sshbox.TUI

	if useUI {
		tui = sshbox.NewTUI(absDirs[0], "")
		mon = tui
	} else {
		mon = sshbox.NewPlainMonitor(verbose)
	}

	mgr, err := sshbox.NewManager(absDirs, mon,
		sshbox.WithVerbose(verbose),
	)
	if err != nil {
		if tui != nil {
			tui.Close()
		}
		log.Fatalf("Failed to initialize jails: %v", err)
	}

	if useUI {
		tui.SetJails(mgr.Jails())
		if err := tui.Start(); err != nil {
			log.Printf("Failed to start TUI, falling back to plain logs: %v", err)
			useUI = false
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- mgr.Serve(host)
	}()

	if useUI {
		defer tui.Close()
		select {
		case err := <-serverDone:
			tui.Close()
			if err != nil {
				log.Printf("Server exited: %v", err)
			}
		case <-tui.QuitChan():
			mgr.Close()
			tui.Close()
		case <-sigCh:
			mgr.Close()
			tui.Close()
		}
	} else {
		select {
		case err := <-serverDone:
			if err != nil {
				log.Printf("Server exited: %v", err)
			}
		case <-sigCh:
			mgr.Close()
			log.Printf("Shutting down...")
		}
	}
}
