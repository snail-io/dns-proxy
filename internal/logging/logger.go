package logging

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	maxTotalSizeGB = 50
	cleanupInterval = 1 * time.Hour
)

var (
	mu      sync.Mutex
	logFile *os.File
	writer  *bufio.Writer
	logDir  string
)

func Init(dir string) {
	logDir = dir
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		log.Printf("create log dir failed: %v", err)
		return
	}

	if err := openTodayLog(); err != nil {
		log.Printf("open log file failed: %v", err)
		return
	}

	go monitorAndRotate()
	go cleanupOldLogs()
}

func openTodayLog() error {
	mu.Lock()
	defer mu.Unlock()

	if writer != nil {
		writer.Flush()
	}
	if logFile != nil {
		logFile.Close()
	}

	today := time.Now().Format("2006-01-02")
	logPath := filepath.Join(logDir, "dns-proxy-"+today+".log")

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	logFile = file
	writer = bufio.NewWriterSize(file, 64*1024)

	log.SetOutput(io.MultiWriter(os.Stdout, &logWriter{}))
	log.SetFlags(log.LstdFlags)
	return nil
}

type logWriter struct{}

func (w *logWriter) Write(p []byte) (int, error) {
	mu.Lock()
	defer mu.Unlock()
	if writer == nil {
		return len(p), nil
	}
	return writer.Write(p)
}

func monitorAndRotate() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		today := time.Now().Format("2006-01-02")
		currentPath := filepath.Join(logDir, "dns-proxy-"+today+".log")

		mu.Lock()
		if logFile != nil {
			filePath, _ := filepath.Abs(logFile.Name())
			currentAbs, _ := filepath.Abs(currentPath)
			if filePath != currentAbs {
				writer.Flush()
				logFile.Close()

				file, err := os.OpenFile(currentAbs, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
				if err != nil {
					log.Printf("rotate log file failed: %v", err)
					mu.Unlock()
					continue
				}
				logFile = file
				writer = bufio.NewWriterSize(file, 64*1024)
				log.SetOutput(io.MultiWriter(os.Stdout, &logWriter{}))
			}
		}
		mu.Unlock()
	}
}

func cleanupOldLogs() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		doCleanup()
	}
}

func doCleanup() {
	files, err := filepath.Glob(filepath.Join(logDir, "dns-proxy-*.log"))
	if err != nil {
		return
	}

	type fileInfo struct {
		path    string
		modTime time.Time
		size    int64
	}

	var infos []fileInfo
	var totalSize int64

	for _, f := range files {
		stat, err := os.Stat(f)
		if err != nil {
			continue
		}
		if stat.IsDir() {
			continue
		}
		infos = append(infos, fileInfo{
			path:    f,
			modTime: stat.ModTime(),
			size:    stat.Size(),
		})
		totalSize += stat.Size()
	}

	maxSize := int64(maxTotalSizeGB) * 1024 * 1024 * 1024
	if totalSize <= maxSize {
		return
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].modTime.Before(infos[j].modTime)
	})

	for _, info := range infos {
		if totalSize <= maxSize {
			break
		}

		if err := os.Remove(info.path); err != nil {
			continue
		}

		totalSize -= info.size
	}
}

func Flush() {
	mu.Lock()
	defer mu.Unlock()
	if writer != nil {
		writer.Flush()
	}
	if logFile != nil {
		logFile.Sync()
	}
}

func WriteToFile(p []byte) (int, error) {
	mu.Lock()
	defer mu.Unlock()
	if writer == nil {
		return len(p), nil
	}
	return writer.Write(p)
}