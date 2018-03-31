package bturn

import (
	"bytes"
	"encoding/binary"
)

type StunMessage struct {
	*bytes.Buffer
}

func NewStunMessage() *StunMessage {
	const defaultBuffer = 512
	return &StunMessage{
		Buffer: bytes.NewBuffer(make([]byte, 0, defaultBuffer)),
	}
}

func (s *StunMessage) Set(method uint16, transID []byte) {
	binary.Write(s, binary.BigEndian, method)
	s.WriteByte(0)
	s.WriteByte(0)
	s.Write(transID)
}

func (s *StunMessage) Bytes() []byte {
	buf := s.Buffer.Bytes()
	binary.BigEndian.PutUint16(buf[StunLengthPtr:], uint16(len(buf[HeaderLength:])))
	return buf
}
