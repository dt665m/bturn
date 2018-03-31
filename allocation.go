package bturn

import (
	"net"
	"time"
)

type allocation struct {
	reflexAddr *net.UDPAddr
	expiry     time.Time

	//tracking
	wBytes, rBytes         int
	wDatagrams, rDatagrams int
}

type channelBind struct {
	peerAddr *net.UDPAddr
	expiry   time.Time

	//tracking
	wBytes, rBytes         int
	wDatagrams, rDatagrams int
}
