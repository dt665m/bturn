package bturn

import (
	"bytes"
	"encoding/binary"
	"net"
)

type AttributeValidator func(attribs []*RawAttribute) bool

// Attribute TLV
type RawAttribute struct {
	Type   Attribute
	Length uint16
	Value  []byte
}

func (r *RawAttribute) AsRequestedTransport() (byte, bool) {
	if r != nil && len(r.Value) >= 1 {
		return r.Value[0], true
	}
	return 0, false
}

func (r *RawAttribute) AsChannelNumber() (uint16, bool) {
	if r != nil {
		return be.Uint16(r.Value), true
	}
	return 0, false
}

func (r *RawAttribute) AsXorMappedAddress(transactionID []byte) (*net.UDPAddr, bool) {
	if r == nil {
		return nil, false
	}
	ipFamily := be.Uint16(r.Value[0:2])
	if ipFamily != IPv4Flag { //&& ipFamily != IPv6Flag {
		return nil, false
	}

	addr := &net.UDPAddr{IP: make([]byte, net.IPv6len)}
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
			log.Debugf("attribute value read failed, expected len %v, read %v, type: %v error: %v",
				attrib.Length, n, attrib.Type, err)
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

func WriteChannelNumber(buf *bytes.Buffer, ch uint16) {
	binary.Write(buf, be, uint16(AttribChannelNumber))
	binary.Write(buf, be, uint16(2))
	binary.Write(buf, be, ch)
	buf.WriteByte(0)
	buf.WriteByte(0)
}

func WriteXorMappedAddress(buf *bytes.Buffer, addr *net.UDPAddr, transactionID []byte) {
	var (
		family = IPv4Flag
		ip     = addr.IP.To16()
	)
	if isIPv4(addr.IP) {
		ip = ip[12:16] // like in ip.To4()
	} else {
		family = IPv6Flag
	}

	value := make([]byte, net.IPv6len)
	binary.BigEndian.PutUint16(value[0:2], family)
	binary.BigEndian.PutUint16(value[2:4], uint16(addr.Port^MagicCookie>>16))
	xorBytes(value[4:4+len(ip)], ip, transactionID)
	binary.Write(buf, be, uint16(AttribXORMappedAddress))
	binary.Write(buf, be, uint16(net.IPv6len))
	buf.Write(value)
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
