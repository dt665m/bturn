package main

import (
	"net"
	"time"

	"github.com/dt665m/bturn"
)

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp4", ":8090")
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}
	conn.SetReadBuffer(8192)
	bturn.SetLogger(bturn.NewDefaultLogger())

	s, err := bturn.New(conn)
	if err != nil {
		panic(err)
	}
	go func() {
		s.Listen()
	}()

	time.Sleep(30 * time.Second)
	conn.Close()
}
