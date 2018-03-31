package bturn

import (
	"bytes"
	"encoding/binary"
	"net"
)

type Attribute uint16

// STUN Required Attributes
const (
	AttribMappedAddress     Attribute = 0x0001
	AttribUsername          Attribute = 0x0006
	AttribMessageIntegrity  Attribute = 0x0008
	AttribErrorCode         Attribute = 0x0009
	AttribUnknownAttributes Attribute = 0x000A
	AttribRealm             Attribute = 0x0014
	AttribNonce             Attribute = 0x0015
	AttribXORMappedAddress  Attribute = 0x0020
)

// STUN Optional Attributes
const (
	AttribSoftware        Attribute = 0x8022
	AttribAlternateServer Attribute = 0x8023
	AttribFingerprint     Attribute = 0x8028
)

// TURN Expanded Attributes
const (
	AttribChannelNumber      Attribute = 0x000C // CHANNEL-NUMBER
	AttribLifetime           Attribute = 0x000D // LIFETIME
	AttribXORPeerAddress     Attribute = 0x0012 // XOR-PEER-ADDRESS
	AttribData               Attribute = 0x0013 // DATA
	AttribXORRelayedAddress  Attribute = 0x0016 // XOR-RELAYED-ADDRESS
	AttribEvenPort           Attribute = 0x0018 // EVEN-PORT
	AttribRequestedTransport Attribute = 0x0019 // REQUESTED-TRANSPORT
	AttribDontFragment       Attribute = 0x001A // DONT-FRAGMENT
	AttribReservationToken   Attribute = 0x0022 // RESERVATION-TOKEN
)

type AttributeValidator func(attribs []*RawAttribute) bool

// Attribute TLV
type RawAttribute struct {
	Type   Attribute
	Length uint16
	Value  []byte
}

func (r *RawAttribute) AsRequestedTransport() (byte, bool) {
	if r != nil && r.Value[0] == 17 {
		return 17, true
	}
	return 0, false
}

func (r *RawAttribute) AsChannelNumber() uint16 {
	if r != nil {
		return be.Uint16(r.Value)
	}
	return 0
}

func (r *RawAttribute) AsXorMappedAddress(transactionID []byte) (*net.UDPAddr, bool) {
	ipFamily := be.Uint16(r.Value[0:2])
	if ipFamily != IPv4Flag { //&& ipFamily != IPv6Flag {
		return nil, false
	}

	addr := &net.UDPAddr{IP: make([]byte, 16)}
	addr.Port = int(be.Uint16(r.Value[2:4])) ^ (MagicCookie >> 16)

	xorBytes(addr.IP, r.Value[4:], transactionID)
	if ipFamily == IPv4Flag {
		addr.IP = addr.IP[:4]
	}
	return addr, true
}

func ParseAttributes(data []byte) []*RawAttribute {
	ra := []*RawAttribute{}
	//	b := buf
	buf := bytes.NewBuffer(data)
	for {
		attrib := &RawAttribute{}
		if err := binary.Read(buf, be, &attrib.Type); err != nil {
			return ra
		}
		if err := binary.Read(buf, be, &attrib.Length); err != nil {
			return ra
		}
		paddedLen := getPadding(int(attrib.Length))
		attrib.Value = make([]byte, paddedLen)
		if n, err := buf.Read(attrib.Value); err != nil {
			log.Debugf("attribute value read failed, expected len %v, read %v, error: %v", attrib.Length, n, err)
			return ra
		}
		//trim padding
		attrib.Value = attrib.Value[:int(attrib.Length)]
		ra = append(ra, attrib)
	}
}

func GetAttribute(aType Attribute, attribs []*RawAttribute) *RawAttribute {
	for _, a := range attribs {
		if a.Type == aType {
			return a
		}
	}
	return nil
}

func WriteRequestedTransport(buf *bytes.Buffer, tranport byte) {
	binary.Write(buf, be, uint16(AttribRequestedTransport))
	binary.Write(buf, be, uint16(1))
	buf.WriteByte(UDPTransport)
	//pad
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
}

func WriteErrorAttribute(buf *bytes.Buffer, code int) {
	const (
		TLLen     = 4
		ReasonLen = 4
	)
	reason := errReasons[code]
	valueLen := len(reason)
	padding := 0
	if valueLen%Padding != 0 {
		padding = getPadding(valueLen) - valueLen
	}

	binary.Write(buf, be, uint16(AttribErrorCode))
	binary.Write(buf, be, uint16(valueLen)) //length is without padding
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(byte(code % 100))
	buf.WriteByte(byte(code / 100))
	buf.Write(reason)
	for i := 0; i < padding; i++ {
		buf.WriteByte(0)
	}
}

func getPadding(l int) int {
	n := Padding * (l / Padding)
	if n < l {
		n += Padding
	}
	return n
}

func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
