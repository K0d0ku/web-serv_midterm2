package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	sessionFile *os.File
)

func InitLogger() {
	if err := os.MkdirAll("logs", os.ModePerm); err != nil {
		panic(err)
	}

	sessionFile = createLogFile()

	multi := zerolog.MultiLevelWriter(
		zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339},
		sessionFile,
	)

	log.Logger = zerolog.New(multi).With().Timestamp().Logger()
	log.Info().Msg("Zerolog initialized")
}

func createLogFile() *os.File {
	now := time.Now()
	name := fmt.Sprintf("logs/log_%s.json", now.Format("2006-01-02_15-04-05"))
	f, err := os.Create(filepath.Clean(name))
	if err != nil {
		panic(err)
	}
	return f
}

func RotateLog() {
	now := time.Now()
	currentHour := now.Format("2006-01-02_15")
	if sessionFile == nil {
		sessionFile = createLogFile()
		return
	}

	// extract hour from current file
	currentFileHour := sessionFile.Name()[len("logs/log_") : len("logs/log_")+13] // YYYY-MM-DD_HH
	if currentFileHour != currentHour {
		sessionFile.Close()
		sessionFile = createLogFile()
		log.Logger = zerolog.New(zerolog.MultiLevelWriter(
			zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339},
			sessionFile,
		)).With().Timestamp().Logger()
		log.Info().Msg("Log rotated due to hour change")
	}
}

func LogEvent(event string, userId string, role string, status string, details map[string]interface{}) {
	RotateLog()
	log.Info().
		Str("event", event).
		Str("userId", userId).
		Str("role", role).
		Str("status", status).
		Fields(details).
		Msg(event)
}

func LogRotation() {
	today := time.Now().Format("2006-01-02")
	logFile := "logs/" + today + ".log"

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	_ = f
}
