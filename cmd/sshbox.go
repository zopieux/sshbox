package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/term"

	"sshbox"
)

func main() {
	var port int
	var host string
	var workDir string
	var verbose bool
	var enableSCP bool
	var enableGPU bool
	var enableNet bool
	var enableForward bool
	var noUI bool

	flag.IntVar(&port, "p", 2222, "Port to listen on (default: 2222)")
	flag.IntVar(&port, "port", 2222, "Port to listen on (default: 2222)")
	flag.StringVar(&host, "host", "0.0.0.0", "Host/interface to listen on (default: 0.0.0.0)")
	flag.StringVar(&workDir, "dir", ".", "Working directory to jail and serve (defaults to current directory)")
	flag.BoolVar(&verbose, "v", false, "Log executed commands and detailed activity (default: disabled)")
	flag.BoolVar(&verbose, "verbose", false, "Log executed commands and detailed activity (default: disabled)")
	flag.BoolVar(&enableSCP, "scp", false, "Enable scp support inside the jail (default: disabled)")
	flag.BoolVar(&enableGPU, "gpu", false, "Enable GPU and host /dev access inside the jail (default: disabled)")
	flag.BoolVar(&enableNet, "net", false, "Enable network access inside the jail (default: disabled)")
	flag.BoolVar(&enableForward, "forward", false, "Enable remote port forwarding (default: disabled)")
	flag.BoolVar(&noUI, "no-ui", false, "Disable TUI monitoring and use plain logs (default: false)")
	flag.Parse()

	listenAddr := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()

	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		absWorkDir = workDir
	}

	useUI := !noUI && term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd()))

	var mon sshbox.Monitor
	var tui *sshbox.TUI

	if useUI {
		tui = sshbox.NewTUI(absWorkDir, listenAddr)
		mon = tui
	} else {
		mon = sshbox.NewPlainMonitor(verbose)
	}

	srv, err := sshbox.NewServer(absWorkDir,
		sshbox.WithVerbose(verbose),
		sshbox.WithSCP(enableSCP),
		sshbox.WithGPU(enableGPU),
		sshbox.WithNet(enableNet),
		sshbox.WithForward(enableForward),
		sshbox.WithMonitor(mon),
	)
	if err != nil {
		if tui != nil {
			tui.Close()
		}
		log.Fatalf("Failed to initialize server: %v", err)
	}

	mon.Log("sshbox listening on %s (sandboxed root: %s)", listenAddr, srv.WorkDir)

	if useUI {
		if err := tui.Start(); err != nil {
			log.Printf("Failed to start TUI, falling back to plain logs: %v", err)
			useUI = false
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- srv.Serve(listener)
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
			listener.Close()
			tui.Close()
		case <-sigCh:
			listener.Close()
			tui.Close()
		}
	} else {
		select {
		case err := <-serverDone:
			if err != nil {
				log.Printf("Server exited: %v", err)
			}
		case <-sigCh:
			listener.Close()
			log.Printf("Shutting down...")
		}
	}
}
