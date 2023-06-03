package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Severity string

const (
	SevError Severity = "ERROR"
	SevWarn  Severity = "WARN"
	SevInfo  Severity = "INFO"
)

type Logger struct {
	mu  sync.Mutex
	out io.Writer
	buf []byte
}

type FileLog struct {
	Logger
	file     *os.File
	filePath string
}

func (l *Logger) Output(sev Severity, calldepth int, format string, v ...interface{}) error {
	// Get this information early, in UTC TZ.
	now := time.Now().UTC()

	// Format message.
	s := fmt.Sprintf(format, v...)
	s = strings.TrimRight(s, "\n")

	// Get caller info first, before obtaining the lock.
	_, file, line, ok := runtime.Caller(calldepth)
	if !ok {
		file = "???"
		line = 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.buf = l.buf[:0]
	l.formatHeader(&l.buf, sev, now, file, line)
	l.buf = append(l.buf, s...)
	l.buf = append(l.buf, '\t')
	l.buf = append(l.buf, '\n')

	_, err := l.out.Write(l.buf)
	return err
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

func NewFileLog(path string) (*FileLog, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %v", err)
	}

	logger := &FileLog{
		file:     file,
		filePath: path,
	}

	logger.SetOutput(file)

	return logger, nil
}

func (f *FileLog) LogPath() string {
	return f.filePath
}

// Pass negative wid to avoid zero-padding.
func itoa(buf *[]byte, i int, wid int) {
	var b [32]byte
	bp := len(b) - 1
	for i >= 10 || wid > 1 {
		wid--
		q := i / 10
		b[bp] = byte('0' + i - q*10)
		bp--
		i = q
	}

	// i < 10
	b[bp] = byte('0' + i)
	*buf = append(*buf, b[bp:]...)
}

func (l *Logger) formatHeader(buf *[]byte, sev Severity, t time.Time, file string, line int) {
	*buf = append(*buf, sev...)
	*buf = append(*buf, '\t')

	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	itoa(buf, year, 4)
	*buf = append(*buf, '-')
	itoa(buf, int(month), 2)
	*buf = append(*buf, '-')
	itoa(buf, day, 2)
	*buf = append(*buf, 'T')
	itoa(buf, hour, 2)
	*buf = append(*buf, ':')
	itoa(buf, min, 2)
	*buf = append(*buf, ':')
	itoa(buf, sec, 2)
	*buf = append(*buf, '.')
	itoa(buf, t.Nanosecond()/1e3, 6)
	*buf = append(*buf, 'Z')
	*buf = append(*buf, '\t')

	file = filepath.Base(file)
	*buf = append(*buf, file...)
	*buf = append(*buf, ':')
	itoa(buf, line, -1)
	*buf = append(*buf, ": "...)
	*buf = append(*buf, '\t')
}
