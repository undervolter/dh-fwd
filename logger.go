package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	logMu   sync.Mutex
	logFile *os.File
)

const defaultLogFile = "dh-fwd.log"

func initLogger(path string) error {
	logMu.Lock()
	defer logMu.Unlock()

	if path == "" {
		path = defaultLogFile
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	logFile = f

	banner := fmt.Sprintf("\n=== dh-fwd %s session started at %s ===\n",
		Version, time.Now().Format("2006-01-02 15:04:05.000"))
	_, _ = logFile.WriteString(banner)
	return nil
}

func closeLogger() {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
}

func writeLog(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()

	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	line := fmt.Sprintf("[%s] %s\n", timestamp, msg)

	if logFile != nil {
		_, _ = logFile.WriteString(line)
	} else {
		fmt.Println(msg)
	}
}
