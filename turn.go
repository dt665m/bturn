package bturn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

var (
	be = binary.BigEndian
)

type TurnOption func(*TurnService) error

func WithMagicCookie(m uint32) TurnOption {
	return func(s *TurnService) error {
		binary.BigEndian.PutUint32(s.magicCookieBytes, m)
		s.magicCookie = m
		return nil
	}
}

func WithReadBufferSize(n int) TurnOption {
	return func(s *TurnService) error {
		if n < 512 {
			return errors.New("buffer should be at least 512 in size")
		}
		s.readBufferSize = n
		return nil
	}
}

func WithAllocationTimeout(d time.Duration) TurnOption {
	return func(s *TurnService) error {
		s.allocationTimeout = d
		return nil
	}
}

func WithChannelTimeout(d time.Duration) TurnOption {
	return func(s *TurnService) error {
		s.channelTimeout = d
		return nil
	}
}

func WithGCPeriod(d time.Duration) TurnOption {
	return func(s *TurnService) error {
		s.gcPeriod = d
		return nil
	}
}

func WithAttributeValidator(v AttributeValidator) TurnOption {
	return func(s *TurnService) error {
		if v == nil {
			return errors.New("attribute validator cannot be nil")
		}
		s.allocCheck = v
		return nil
	}
}

type TurnService struct {
	mu       sync.RWMutex
	allocMap map[uint64]*allocation
	chanMap  map[uint16]*channelBind
	conn     *net.UDPConn

	//options
	allocationTimeout time.Duration
	channelTimeout    time.Duration
	gcPeriod          time.Duration
	magicCookieBytes  []byte
	magicCookie       uint32
	readBufferSize    int
	allocCheck        AttributeValidator

	quitCh chan struct{}
}

func New(conn *net.UDPConn, opts ...TurnOption) (*TurnService, error) {
	if conn == nil {
		return nil, errors.New("connection must not be nil")
	}
	s := &TurnService{
		allocMap: make(map[uint64]*allocation),
		chanMap:  make(map[uint16]*channelBind),
		conn:     conn,

		//sensible default options
		readBufferSize:    1500,
		allocationTimeout: 10 * time.Minute,
		channelTimeout:    10 * time.Minute,
		gcPeriod:          30 * time.Second,
		magicCookieBytes:  make([]byte, 4),
		magicCookie:       MagicCookie,
		allocCheck:        func(attribs []*RawAttribute) bool { return true },
		quitCh:            make(chan struct{}),
	}
	//use default stun magicCookie first
	binary.BigEndian.PutUint32(s.magicCookieBytes, MagicCookie)
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	go func() {
		for {
			select {
			case <-s.quitCh:
				log.Infoln("relayservice gc stopped")
				return
			case <-time.Tick(s.gcPeriod):
				s.mu.Lock()
				now := time.Now()
				for k, alloc := range s.allocMap {
					if alloc.expiry.Sub(now) <= 0 {
						delete(s.allocMap, k)
					} else {
						log.Infof("%v alloc expires in %v", k, alloc.expiry.Sub(now))
					}
				}
				for k, chBind := range s.chanMap {
					if chBind.expiry.Sub(now) <= 0 {
						delete(s.chanMap, k)
					} else {
						log.Infof("%v chbind expires in %v", k, chBind.expiry.Sub(now))
					}
				}
				s.mu.Unlock()
			}
		}
	}()

	return s, nil
}

func (s *TurnService) Listen() {
	buf := make([]byte, s.readBufferSize)

Listen:
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Infoln("connection terminated:", err)
			close(s.quitCh)
			break Listen
		}
		if s.tryChannelData(n, addr, buf) {
			continue
		}
		if n < HeaderLength {
			log.Infoln("spam: ", buf)
			continue
		}

		sMethod := binary.BigEndian.Uint16(buf[:2])
		switch sMethod {
		case AllocateRequest:
			log.Infoln("allocate request")
			s.allocate(n, addr, buf)
		case RefreshRequest:
			log.Infoln("refresh request")
			s.refresh(n, addr, buf)
		case ChannelBindRequest:
			log.Infoln("channelbind request")
			s.channelBind(n, addr, buf)
		case SendIndication:
			log.Infoln("send indication")
			s.send(n, addr, buf)
		case CreatePermissionRequest:
			log.Infoln("create permission request")
			s.createPermission(n, addr, buf)
		default:
			log.Infoln("method not implemented:", sMethod)
		}
	}
}

func (s *TurnService) tryChannelData(n int, addr *net.UDPAddr, buf []byte) bool {
	if n < 2 {
		return true
	}

	ch := binary.BigEndian.Uint16(buf[:2])
	if ChannelDataStart&ch == ChannelDataStart && ch <= ChannelDataEnd {
		//valid channel range.
		chBind, found := s.chanMap[ch]
		if found {
			pLen := int(binary.BigEndian.Uint16(buf[2:]))
			if len(buf[4:n]) < pLen {
				log.Debugf("channel data length %v too large %v", pLen, buf)
				return true
			}
			chBind.expiry = time.Now().Add(s.channelTimeout)
			wN, err := s.conn.WriteToUDP(buf[4:n], chBind.peerAddr)
			if err != nil {
				log.Debugf("udp write to %v error: %v", addr, err)
			}
			chBind.rDatagrams++
			chBind.rBytes += n
			chBind.wDatagrams++
			chBind.wBytes += wN
		}
		return true
	}
	return false
}

func (s *TurnService) allocate(n int, addr *net.UDPAddr, buf []byte) {
	connKey, ok := udpAddrToKey(addr)
	if !ok {
		log.Debugf("unhandled addr type: ", addr)
		return
	}

	transID := buf[StunTransactionIDPtr:HeaderLength]
	if bytes.Equal(transID[:StunTransactionIDPtr], s.magicCookieBytes) { //check magic cookie is ok
		sLen := binary.BigEndian.Uint16(buf[StunLengthPtr:]) //stun message length
		if len(buf[HeaderLength:]) < int(sLen) {
			log.Debugf("stun message payload and length incorrect, expected %v got %v", sLen, len(buf[HeaderLength:]))
			return
		}
		m := NewStunMessage()
		attribs := ParseAttributes(buf[HeaderLength:n])
		if trp, ok := GetAttribute(AttribRequestedTransport, attribs).AsRequestedTransport(); !ok {
			log.Debugf("stun attribute requested-transport missing status")
			m.Set(AllocateErrorResponse, transID)
			WriteErrorAttribute(m.Buffer, StatusBadRequest)
			mBytes := m.Bytes()
			s.conn.WriteToUDP(mBytes, addr)
			return
		} else if trp != UDPTransport {
			log.Debugf("stun attribute requested-transport incorrect expected %v got %v", UDPTransport, trp)
			m.Set(AllocateErrorResponse, transID)
			WriteErrorAttribute(m.Buffer, StatusUnsupportedTransportProtocol)
			mBytes := m.Bytes()
			s.conn.WriteToUDP(mBytes, addr)
			return
		}
		//custom allocation checking
		if !s.allocCheck(attribs) {
			m.Set(AllocateErrorResponse, transID)
			WriteErrorAttribute(m.Buffer, StatusUnauthorized)
			mBytes := m.Bytes()
			s.conn.WriteToUDP(mBytes, addr)
			return
		}

		s.mu.Lock()
		alloc, found := s.allocMap[connKey]
		if !found {
			alloc = &allocation{
				connKey:    connKey,
				reflexAddr: addr,
				expiry:     time.Now().Add(10 * time.Minute),
			}
			s.allocMap[connKey] = alloc
		}
		s.mu.Unlock()

		m.Set(AllocateResponse, transID)
		nW, err := s.conn.WriteToUDP(m.Bytes(), addr)
		if err != nil {
			log.Debugf("udp write to %v error: %v", addr, err)
		}
		alloc.rBytes += n
		alloc.rDatagrams++
		alloc.wBytes += nW
		alloc.wDatagrams++
	} else {
		log.Debugln("allocateMethod spam:", buf[:n])
	}
}

func (s *TurnService) refresh(n int, addr *net.UDPAddr, buf []byte) {
	connKey, ok := udpAddrToKey(addr)
	if !ok {
		log.Debugln("unhandled addr type:", addr)
		return
	}

	transID := buf[StunTransactionIDPtr:HeaderLength]
	if bytes.Equal(transID[:StunTransactionIDPtr], s.magicCookieBytes) { //check magic cookie is ok
		m := NewStunMessage()
		s.mu.RLock()
		alloc, found := s.allocMap[connKey]
		s.mu.RUnlock()
		if !found {
			m.Set(RefreshErrorResponse, transID)
			WriteErrorAttribute(m.Buffer, StatusConnectionTimeoutOrFailure)
			s.conn.WriteToUDP(m.Bytes(), addr)
			return
		}
		alloc.expiry = time.Now().Add(s.allocationTimeout)
		m.Set(RefreshResponse, transID)

		nW, err := s.conn.WriteToUDP(m.Bytes(), addr)
		if err != nil {
			log.Debugf("udp write to %v error: %v", addr, err)
		}
		alloc.rBytes += n
		alloc.rDatagrams++
		alloc.wBytes += nW
		alloc.wDatagrams++
	}
}

func (s *TurnService) channelBind(n int, addr *net.UDPAddr, buf []byte) {
	connKey, ok := udpAddrToKey(addr)
	if !ok {
		log.Debugln("unhandled addr type:", addr)
		return
	}
	s.mu.RLock()
	alloc, found := s.allocMap[connKey]
	if !found {
		log.Infoln("channelBind requested from unallocated:", addr)
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	transID := buf[StunTransactionIDPtr:HeaderLength]
	if bytes.Equal(transID[:StunTransactionIDPtr], s.magicCookieBytes) { //check magic cookie is ok
		sLen := binary.BigEndian.Uint16(buf[StunLengthPtr:]) //stun message length
		if len(buf[HeaderLength:]) < int(sLen) {
			log.Debugf("stun message payload and length incorrect, expected %v got %v", sLen, len(buf[HeaderLength:]))
			return
		}

		var (
			m       = NewStunMessage()
			attribs = ParseAttributes(buf[HeaderLength:n])
			ch      uint16
			xAddr   *net.UDPAddr
		)
		ch, ok = GetAttribute(AttribChannelNumber, attribs).AsChannelNumber()
		if !ok {
			log.Infoln("channel attribute missing")
			goto Fail
		}
		if ChannelDataStart&ch != ChannelDataStart && ch >= ChannelDataEnd {
			log.Infoln("invalid channel range: ", ch)
			goto Fail
		}

		xAddr, ok = GetAttribute(AttribXORMappedAddress, attribs).AsXorMappedAddress(transID)
		if !ok {
			log.Infoln("xor-mapped-address missing")
			goto Fail
		}
		if !isIPv4(xAddr.IP) {
			log.Infoln("ipv6 not yet supported")
			goto Fail
		}

		if ChannelDataStart&ch == ChannelDataStart && ch <= ChannelDataEnd {
			s.mu.RLock()
			channel, found := s.chanMap[ch]
			s.mu.RUnlock()
			if !found {
				s.mu.Lock()
				s.chanMap[ch] = &channelBind{
					allocation: alloc,
					peerAddr:   xAddr,
					expiry:     time.Now().Add(s.channelTimeout),
				}
				s.mu.Unlock()
				log.Debugf("ch %v mapped by %v to peer %v", ch, addr, xAddr)
				goto Success
			} else if channel.allocation.connKey == connKey {
				channel.expiry = time.Now().Add(s.channelTimeout)
				channel.peerAddr = xAddr
				log.Debugf("ch %v mapped %v to peer %v refreshed", ch, addr, xAddr)
				goto Success
			} else {
				log.Debugf("ch %v already mapped by another allocation", ch)
				goto Fail
			}
		}

	Success:
		{
			m.Set(ChannelBindResponse, transID)
			nW, err := s.conn.WriteToUDP(m.Bytes(), addr)
			if err != nil {
				log.Debugf("udp write to %v error: %v", addr, err)
			}
			alloc.rBytes += n
			alloc.rDatagrams++
			alloc.wBytes += nW
			alloc.wDatagrams++
			return
		}

	Fail:
		{
			m.Set(ChannelBindErrorResponse, transID)
			WriteErrorAttribute(m.Buffer, StatusBadRequest)
			nW, err := s.conn.WriteToUDP(m.Bytes(), addr)
			if err != nil {
				log.Debugf("udp write to %v error: %v", addr, err)
			}
			alloc.rBytes += n
			alloc.rDatagrams++
			alloc.wBytes += nW
			alloc.wDatagrams++
			return
		}
	}
}

func (s *TurnService) createPermission(n int, addr *net.UDPAddr, buf []byte) {
	log.Debugln("send method not implemented")
}

func (s *TurnService) send(n int, addr *net.UDPAddr, buf []byte) {
	log.Debugln("send method not implemented")
}

func isIPv4(ip net.IP) bool {
	return len(ip) == net.IPv4len ||
		(isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff) // Copied from net.IP.To4
}

func udpAddrToKey(addr *net.UDPAddr) (uint64, bool) {
	if isIPv4(addr.IP) {
		b := make([]byte, 8)
		b[0] = addr.IP[12]
		b[1] = addr.IP[13]
		b[2] = addr.IP[14]
		b[3] = addr.IP[15]
		binary.BigEndian.PutUint16(b[4:], uint16(addr.Port))

		return binary.BigEndian.Uint64(b), true
	}
	return 0, false
}

func isZeros(p net.IP) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
}
