package main

import (
	"flag"
	"fmt"
	"log"
	"net"

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
	flag.Parse()

	srv, err := sshbox.NewServer(workDir,
		sshbox.WithVerbose(verbose),
		sshbox.WithSCP(enableSCP),
		sshbox.WithGPU(enableGPU),
		sshbox.WithNet(enableNet),
		sshbox.WithForward(enableForward),
	)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	listenAddr := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()

	log.Printf("sshbox listening on %s (sandboxed root: %s)", listenAddr, srv.WorkDir)
	if err := srv.Serve(listener); err != nil {
		log.Printf("Server exited: %v", err)
	}
}
