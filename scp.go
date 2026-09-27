package sshbox

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type scpOptions struct {
	sink      bool // -t
	source    bool // -f
	recursive bool // -r
	preserve  bool // -p
	isDir     bool // -d
	target    string
}

func parseSCPArgs(args []string) (*scpOptions, error) {
	opts := &scpOptions{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-t" {
			opts.sink = true
		} else if arg == "-f" {
			opts.source = true
		} else if arg == "-r" {
			opts.recursive = true
		} else if arg == "-p" {
			opts.preserve = true
		} else if arg == "-d" {
			opts.isDir = true
		} else if arg == "-v" || arg == "-q" {
			// ignore verbosity / quiet flags
		} else if strings.HasPrefix(arg, "-") {
			// combined flags like -rf or -tr
			for _, ch := range arg[1:] {
				switch ch {
				case 't':
					opts.sink = true
				case 'f':
					opts.source = true
				case 'r':
					opts.recursive = true
				case 'p':
					opts.preserve = true
				case 'd':
					opts.isDir = true
				}
			}
		} else {
			opts.target = arg
		}
	}

	if !opts.sink && !opts.source {
		return nil, fmt.Errorf("scp must specify either -t (sink) or -f (source)")
	}
	if opts.target == "" {
		opts.target = "/work"
	}
	return opts, nil
}

// resolveAndValidatePath maps requested path to host path and enforces:
// "it only accepts dealing with files in /work & /home/bashbox"
func resolveAndValidatePath(baseDir, reqPath string) (string, error) {
	var clean string
	if !strings.HasPrefix(reqPath, "/") {
		clean = path.Clean(path.Join("/work", reqPath))
	} else {
		clean = path.Clean(reqPath)
	}

	// If root, default to /work
	if clean == "/" {
		clean = "/work"
	}

	inWork := clean == "/work" || strings.HasPrefix(clean, "/work/")
	inHome := clean == "/home/bashbox" || strings.HasPrefix(clean, "/home/bashbox/")

	if !inWork && !inHome {
		return "", fmt.Errorf("scp access denied: path %q must be within /work or /home/bashbox", reqPath)
	}

	// Security: prohibit access to .bashbox.toml
	if clean == "/work/.bashbox.toml" || strings.HasPrefix(clean, "/work/.bashbox.toml/") {
		return "", fmt.Errorf("scp access denied: cannot access .bashbox.toml")
	}

	// Hide .home when requested via /work (use /home/bashbox instead)
	if clean == "/work/.home" || strings.HasPrefix(clean, "/work/.home/") {
		return "", fmt.Errorf("scp access denied: cannot access .home via /work; use /home/bashbox")
	}

	workHostDir := filepath.Clean(baseDir)
	homeHostDir := filepath.Clean(filepath.Join(baseDir, ".home"))

	var hostPath string
	if inWork {
		rel := strings.TrimPrefix(clean, "/work")
		rel = strings.TrimPrefix(rel, "/")
		hostPath = filepath.Join(workHostDir, filepath.FromSlash(rel))
	} else {
		rel := strings.TrimPrefix(clean, "/home/bashbox")
		rel = strings.TrimPrefix(rel, "/")
		hostPath = filepath.Join(homeHostDir, filepath.FromSlash(rel))
	}

	hostPath = filepath.Clean(hostPath)

	// Verify no directory traversal outside allowed roots
	relW, errW := filepath.Rel(workHostDir, hostPath)
	relH, errH := filepath.Rel(homeHostDir, hostPath)
	if (errW != nil || strings.HasPrefix(relW, "..")) && (errH != nil || strings.HasPrefix(relH, "..")) {
		return "", fmt.Errorf("scp access denied: directory traversal detected")
	}

	// Double check .bashbox.toml on host
	if hostPath == filepath.Join(workHostDir, ".bashbox.toml") {
		return "", fmt.Errorf("scp access denied: cannot access .bashbox.toml")
	}

	return hostPath, nil
}

func handleSCP(channel ssh.Channel, baseDir string, rawArgs []string) error {
	opts, err := parseSCPArgs(rawArgs)
	if err != nil {
		sendSCPError(channel, err.Error())
		sendExitStatus(channel, err)
		return err
	}

	hostPath, err := resolveAndValidatePath(baseDir, opts.target)
	if err != nil {
		sendSCPError(channel, err.Error())
		sendExitStatus(channel, err)
		return err
	}

	var scpErr error
	if opts.sink {
		scpErr = handleSCPSink(channel, hostPath, opts)
	} else {
		scpErr = handleSCPSource(channel, hostPath, opts)
	}

	if scpErr != nil {
		log.Printf("SCP error: %v", scpErr)
	}
	sendExitStatus(channel, scpErr)
	return scpErr
}

func sendSCPAck(w io.Writer) error {
	_, err := w.Write([]byte{0})
	return err
}

func sendSCPError(w io.Writer, msg string) {
	_, _ = fmt.Fprintf(w, "\x01scp: %s\n", msg)
}

func handleSCPSink(channel ssh.Channel, hostPath string, opts *scpOptions) error {
	// Send initial ACK to begin transfer
	if err := sendSCPAck(channel); err != nil {
		return err
	}

	reader := bufio.NewReader(channel)

	// If destination is a directory or marked as -d, items go inside it
	targetDir := hostPath
	destInfo, err := os.Stat(hostPath)
	if err == nil && destInfo.IsDir() {
		targetDir = hostPath
	} else if err != nil && opts.isDir {
		if err := os.MkdirAll(hostPath, 0755); err != nil {
			sendSCPError(channel, err.Error())
			return err
		}
		targetDir = hostPath
	}

	dirStack := []string{targetDir}

	var mtime, atime time.Time

	for {
		opByte, err := reader.ReadByte()
		if err != nil {
			if errorsIsEOF(err) {
				return nil
			}
			return err
		}

		switch opByte {
		case 0:
			// No-op / ACK from client
			continue
		case '\n':
			continue
		case 'T':
			// Timestamp line: T<mtime> 0 <atime> 0\n
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) >= 4 {
				m, _ := strconv.ParseInt(parts[0], 10, 64)
				a, _ := strconv.ParseInt(parts[2], 10, 64)
				mtime = time.Unix(m, 0)
				atime = time.Unix(a, 0)
			}
			if err := sendSCPAck(channel); err != nil {
				return err
			}

		case 'C':
			// File line: C<mode> <length> <filename>\n
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
			if len(parts) < 3 {
				sendSCPError(channel, "malformed file header")
				return fmt.Errorf("malformed file header: %s", line)
			}

			modeInt, _ := strconv.ParseInt(parts[0], 8, 32)
			size, _ := strconv.ParseInt(parts[1], 10, 64)
			filename := filepath.Base(parts[2])

			if filename == ".bashbox.toml" || filename == ".home" {
				sendSCPError(channel, "access denied: cannot modify .bashbox.toml or .home via /work")
				return fmt.Errorf("attempt to modify restricted file via scp: %s", filename)
			}

			currentDir := dirStack[len(dirStack)-1]
			var destFile string
			if len(dirStack) == 1 && !opts.isDir && (destInfo == nil || !destInfo.IsDir()) {
				// Single file copy directly to requested path
				destFile = hostPath
			} else {
				destFile = filepath.Join(currentDir, filename)
			}

			if err := sendSCPAck(channel); err != nil {
				return err
			}

			// Receive file contents
			if err := writeFileContent(reader, destFile, size, os.FileMode(modeInt)); err != nil {
				sendSCPError(channel, err.Error())
				return err
			}

			if !mtime.IsZero() {
				_ = os.Chtimes(destFile, atime, mtime)
				mtime = time.Time{}
				atime = time.Time{}
			}

			if err := sendSCPAck(channel); err != nil {
				return err
			}

		case 'D':
			// Directory line: D<mode> 0 <dirname>\n
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
			if len(parts) < 3 {
				sendSCPError(channel, "malformed directory header")
				return fmt.Errorf("malformed directory header: %s", line)
			}

			modeInt, _ := strconv.ParseInt(parts[0], 8, 32)
			dirname := filepath.Base(parts[2])

			currentDir := dirStack[len(dirStack)-1]
			newDir := filepath.Join(currentDir, dirname)
			if err := os.MkdirAll(newDir, os.FileMode(modeInt)); err != nil {
				sendSCPError(channel, err.Error())
				return err
			}

			dirStack = append(dirStack, newDir)
			if err := sendSCPAck(channel); err != nil {
				return err
			}

		case 'E':
			// End of directory
			_, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			if len(dirStack) > 1 {
				dirStack = dirStack[:len(dirStack)-1]
			}
			if err := sendSCPAck(channel); err != nil {
				return err
			}

		case 1, 2:
			// Error from client
			errMsg, _ := reader.ReadString('\n')
			return fmt.Errorf("client error: %s", errMsg)

		default:
			sendSCPError(channel, fmt.Sprintf("unsupported command byte: %c", opByte))
			return fmt.Errorf("unsupported command byte: %c", opByte)
		}
	}
}

func writeFileContent(reader io.Reader, destPath string, size int64, mode os.FileMode) error {
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.CopyN(f, reader, size); err != nil {
		return fmt.Errorf("copy content to %s: %w", destPath, err)
	}

	// Read terminating 0x00 byte sent by client
	var buf [1]byte
	if _, err := io.ReadFull(reader, buf[:]); err != nil {
		return fmt.Errorf("read file trailing ack: %w", err)
	}
	if buf[0] != 0 {
		return fmt.Errorf("expected 0x00 after file content, got %d", buf[0])
	}

	return nil
}

func handleSCPSource(channel ssh.Channel, hostPath string, opts *scpOptions) error {
	reader := bufio.NewReader(channel)

	// Wait for client's initial ACK
	ack, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if ack != 0 {
		return fmt.Errorf("expected 0 from client, got %d", ack)
	}

	st, err := os.Stat(hostPath)
	if err != nil {
		sendSCPError(channel, err.Error())
		return err
	}

	if st.IsDir() {
		if !opts.recursive {
			sendSCPError(channel, fmt.Sprintf("%s is a directory, not a regular file", hostPath))
			return fmt.Errorf("%s is a directory", hostPath)
		}
		return sendSCPTree(channel, reader, hostPath, opts)
	}

	return sendSCPFile(channel, reader, hostPath, st, opts)
}

func sendSCPFile(channel ssh.Channel, reader *bufio.Reader, path string, st os.FileInfo, opts *scpOptions) error {
	if filepath.Base(path) == ".bashbox.toml" {
		sendSCPError(channel, "access denied to .bashbox.toml")
		return fmt.Errorf("access denied to .bashbox.toml")
	}

	if opts.preserve {
		mtime := st.ModTime().Unix()
		atime := mtime
		if _, err := fmt.Fprintf(channel, "T%d 0 %d 0\n", mtime, atime); err != nil {
			return err
		}
		if err := readSCPAck(reader); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(channel, "C%04o %d %s\n", st.Mode().Perm(), st.Size(), filepath.Base(path)); err != nil {
		return err
	}
	if err := readSCPAck(reader); err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		sendSCPError(channel, err.Error())
		return err
	}
	defer f.Close()

	if _, err := io.CopyN(channel, f, st.Size()); err != nil {
		return err
	}

	if err := sendSCPAck(channel); err != nil {
		return err
	}

	return readSCPAck(reader)
}

func sendSCPTree(channel ssh.Channel, reader *bufio.Reader, dirPath string, opts *scpOptions) error {
	st, err := os.Stat(dirPath)
	if err != nil {
		sendSCPError(channel, err.Error())
		return err
	}

	if opts.preserve {
		mtime := st.ModTime().Unix()
		atime := mtime
		if _, err := fmt.Fprintf(channel, "T%d 0 %d 0\n", mtime, atime); err != nil {
			return err
		}
		if err := readSCPAck(reader); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(channel, "D%04o 0 %s\n", st.Mode().Perm(), filepath.Base(dirPath)); err != nil {
		return err
	}
	if err := readSCPAck(reader); err != nil {
		return err
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		sendSCPError(channel, err.Error())
		return err
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == ".bashbox.toml" || name == ".home" {
			continue
		}
		childPath := filepath.Join(dirPath, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.IsDir() {
			if err := sendSCPTree(channel, reader, childPath, opts); err != nil {
				return err
			}
		} else {
			if err := sendSCPFile(channel, reader, childPath, info, opts); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintf(channel, "E\n"); err != nil {
		return err
	}
	return readSCPAck(reader)
}

func readSCPAck(reader *bufio.Reader) error {
	b, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if b == 0 {
		return nil
	}
	errMsg, _ := reader.ReadString('\n')
	return fmt.Errorf("remote scp error (code %d): %s", b, strings.TrimSpace(errMsg))
}

func errorsIsEOF(err error) bool {
	return err == io.EOF || errorsIs(err, io.EOF)
}

func errorsIs(err, target error) bool {
	return strings.Contains(err.Error(), "EOF")
}
