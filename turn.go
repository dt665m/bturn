package bturn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
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
	//use stun magicCookie first
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
						//delete channels also
					} else {
						log.Infof("%v expires in %v", k, alloc.expiry.Sub(now))
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
		//found channel range.
		chBind, found := s.chanMap[ch]
		if found {
			pLen := int(binary.BigEndian.Uint32(buf[4:]))
			if len(buf[8:]) < pLen {
				log.Debugf("channel data length %v too large %v", pLen, buf)
				return true
			}
			chBind.expiry = time.Now().Add(10 * time.Minute)
			wN, err := s.conn.WriteToUDP(buf[8:pLen], chBind.peerAddr)
			if err != nil {
				log.Debugf("udp write to %v error: %v", addr, err)
			}
			chBind.rDatagrams++
			chBind.rBytes += n
			chBind.wDatagrams++
			chBind.wBytes += wN
		}
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
			log.Debugf("stun attribute requested-transport failed got %v parse status %v", trp, ok)
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
		client, found := s.allocMap[connKey]
		if !found {
			client = &allocation{
				expiry: time.Now().Add(10 * time.Minute),
			}
			s.allocMap[connKey] = client
		}
		s.mu.Unlock()

		m.Set(AllocateResponse, transID)
		nW, err := s.conn.WriteToUDP(m.Bytes(), addr)
		if err != nil {
			log.Debugf("udp write to %v error: %v", addr, err)
		}
		client.rBytes += n
		client.rDatagrams++
		client.wBytes += nW
		client.wDatagrams++
	} else {
		log.Debugln("allocateMethod spam:", buf[:n], transID)
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
		s.mu.Lock()
		client, found := s.allocMap[connKey]
		if !found {
			m.Set(RefreshErrorResponse, transID)
			WriteErrorAttribute(m.Buffer, StatusConnectionTimeoutOrFailure)
			s.conn.WriteToUDP(m.Bytes(), addr)
			s.mu.Unlock()
			return
		}
		client.expiry = time.Now().Add(s.allocationTimeout)
		s.mu.Unlock()

		m.Set(RefreshResponse, transID)
		nW, err := s.conn.WriteToUDP(m.Bytes(), addr)
		if err != nil {
			log.Debugf("udp write to %v error: %v", addr, err)
		}
		client.rBytes += n
		client.rDatagrams++
		client.wBytes += nW
		client.wDatagrams++
	}
}

func (s *TurnService) channelBind(n int, addr *net.UDPAddr, buf []byte) {
	connKey, ok := udpAddrToKey(addr)
	if !ok {
		log.Debugln("unhandled addr type:", addr)
		return
	}
	s.mu.Lock()
	_, found := s.allocMap[connKey]
	if !found {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	transID := buf[StunTransactionIDPtr:HeaderLength]
	if bytes.Equal(transID[:StunTransactionIDPtr], s.magicCookieBytes) { //check magic cookie is ok
		sLen := binary.BigEndian.Uint16(buf[StunLengthPtr:]) //stun message length
		if len(buf[HeaderLength:]) < int(sLen) {
			log.Debugf("stun message payload and length incorrect, expected %v got %v", sLen, len(buf[HeaderLength:]))
			return
		}
		m := NewStunMessage()
		attribs := ParseAttributes(buf[HeaderLength:n])
		ch := GetAttribute(AttribChannelNumber, attribs).AsChannelNumber()
		xAddr, ok := GetAttribute(AttribXORMappedAddress, attribs).AsXorMappedAddress(transID)
		if !ok || !isIPv4(addr.IP) {
			log.Debugln("ipv6 not supported")
			m.Set(AllocateErrorResponse, transID)
			WriteErrorAttribute(m.Buffer, StatusBadRequest)
			s.conn.WriteToUDP(m.Bytes(), addr)
			return
		}
		if ChannelDataStart&ch == ChannelDataStart && ch <= ChannelDataEnd {
			s.mu.Lock()
			channel, found := s.chanMap[ch]
			if !found {
				channel = &channelBind{
					peerAddr: xAddr,
					expiry:   time.Now().Add(s.channelTimeout),
				}
				s.chanMap[ch] = channel
				log.Debugf("Channel %v mapped to %v for %v", ch, xAddr, addr)
			}
			if channel.peerAddr == xAddr {

			}
			//check addr == xor-mapped-address or we are already used up, reject
			s.mu.Unlock()
		} else {
			m.Set(RefreshErrorResponse, transID)
			WriteErrorAttribute(m.Buffer, StatusBadRequest)
			s.conn.WriteToUDP(m.Bytes(), addr)
			return
		}
	}
}

func (r *TurnService) data(n int, addr *net.UDPAddr, buf []byte) {
	//not implemented
}

func isIPv4(ip net.IP) bool {
	return isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff // Copied from net.IP.To4
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
