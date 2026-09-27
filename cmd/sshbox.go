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

	flag.IntVar(&port, "p", 2222, "Port to listen on")
	flag.IntVar(&port, "port", 2222, "Port to listen on")
	flag.StringVar(&host, "host", "0.0.0.0", "Host/interface to listen on")
	flag.StringVar(&workDir, "dir", ".", "Working directory to jail and serve (defaults to current directory)")
	flag.Parse()

	srv, err := sshbox.NewServer(workDir)
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
