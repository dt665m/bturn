package bturn

import (
	"net"
	"time"
)

type allocation struct {
	connKey    uint64
	reflexAddr *net.UDPAddr
	expiry     time.Time

	//tracking
	wBytes, rBytes         int
	wDatagrams, rDatagrams int
}

type channelBind struct {
	allocation *allocation
	peerAddr   *net.UDPAddr
	expiry     time.Time

	//tracking
	wBytes, rBytes         int
	wDatagrams, rDatagrams int
}
