package bturn

import (
	"fmt"
	dlog "log"
	"os"
)

var log Logger = &NilLogger{}

type Logger interface {
	Info(...interface{})
	Infoln(...interface{})
	Infof(string, ...interface{})
	Debug(...interface{})
	Debugln(...interface{})
	Debugf(string, ...interface{})
}

func SetLogger(logger Logger) {
	log = logger
}

type NilLogger struct{}

func (l *NilLogger) Info(v ...interface{})                  {}
func (l *NilLogger) Infoln(v ...interface{})                {}
func (l *NilLogger) Infof(format string, v ...interface{})  {}
func (l *NilLogger) Debug(v ...interface{})                 {}
func (l *NilLogger) Debugln(v ...interface{})               {}
func (l *NilLogger) Debugf(format string, v ...interface{}) {}

type DefaultLogger struct {
	*dlog.Logger
}

func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{dlog.New(os.Stderr, "", dlog.LstdFlags|dlog.Lshortfile)}
}
func (l *DefaultLogger) Info(v ...interface{})                 { l.Output(2, fmt.Sprint(v...)) }
func (l *DefaultLogger) Infoln(v ...interface{})               { l.Output(2, fmt.Sprintln(v...)) }
func (l *DefaultLogger) Infof(format string, v ...interface{}) { l.Output(2, fmt.Sprintf(format, v...)) }
func (l *DefaultLogger) Debug(v ...interface{})                { l.Output(2, fmt.Sprint(v...)) }
func (l *DefaultLogger) Debugln(v ...interface{})              { l.Output(2, fmt.Sprintln(v...)) }
func (l *DefaultLogger) Debugf(format string, v ...interface{}) {
	l.Output(2, fmt.Sprintf(format, v...))
}
