package bturn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

var (
	TransactionID = []byte{51, 64, 168, 147, 169, 188, 245, 134, 8, 87, 85, 52}
)

func TestMain(m *testing.M) {
	udpAddr, err := net.ResolveUDPAddr("udp4", ":8090")
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}
	conn.SetReadBuffer(8192)
	log = NewDefaultLogger()

	s, err := New(conn)
	if err != nil {
		panic(err)
	}
	go func() {
		s.Listen()
	}()

	time.Sleep(1)
	ret := m.Run()
	conn.Close()
	os.Exit(ret)
}

func TestPublicBindRequest(t *testing.T) {
	conn, _ := net.Dial("udp", "stun.l.google.com:19302")

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[:2], BindingRequest)
	binary.BigEndian.PutUint32(req[4:8], MagicCookie)
	copy(req[8:20], TransactionID)
	t.Log("Stun Request", req)
	t.Log("Magic Cookie", req[4:8])
	t.Log("TransactionID", req[8:20])

	conn.Write(req)

	resp := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		t.Error(err)
	}
	t.Log("Stun Response", resp[:n])
	t.Log("Payload Length", binary.BigEndian.Uint16(resp[2:]))
	t.Log("Magic Cookie", resp[4:8])
	t.Log("TransactionID", resp[8:20])
	t.Log("Attributes", resp[20:n], len(resp[20:n]))

	attribs := ParseAttributes(resp[HeaderLength:n])
	transaction := make([]byte, TransactionIDLength+4)
	binary.BigEndian.PutUint32(transaction[:4], MagicCookie)
	copy(transaction[4:], TransactionID)
	addr, ok := GetAttribute(AttribXORMappedAddress, attribs).AsXorMappedAddress(transaction)
	if !ok {
		t.Error("unable to parse xormapped address")
	}
	fmt.Println("test:", []byte(addr.IP))
	fmt.Println("test:", addr.IP.String())
	fmt.Println("test:", isIPv4(addr.IP))
	//	XorAttribute  = []byte{0, 32, 0, 8, 0, 1, 213, 217, 253, 151, 244, 59}
}

func TestPrivateTurnFail(t *testing.T) {
	conn, _ := net.Dial("udp", "127.0.0.1:8090")

	req := bytes.NewBuffer(make([]byte, 0, 512))
	binary.Write(req, binary.BigEndian, uint16(AllocateRequest))
	req.WriteByte(0) //zero length
	req.WriteByte(0)
	binary.Write(req, binary.BigEndian, uint32(MagicCookie))
	req.Write(TransactionID)
	WriteRequestedTransport(req, UDPTransport)

	reqBuf := req.Bytes()
	binary.BigEndian.PutUint16(reqBuf[2:4], uint16(len(reqBuf[HeaderLength:])))
	t.Log("Stun Request", reqBuf)
	t.Log("Magic Cookie", reqBuf[4:8])
	t.Log("TransactionID", reqBuf[8:20])
	t.Log("Attributes:", reqBuf[HeaderLength:])

	_, err := conn.Write(reqBuf)
	if err != nil {
		t.Error(err)
	}

	resp := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		t.Error(err)
	}
	//when parsing attributes, we have to check for "padded length" because length is encoded sans padding
	t.Log("Stun Response", resp[:n])
	t.Log("IsAllocateError", binary.BigEndian.Uint16(resp[:2]) == AllocateErrorResponse)
	t.Log("IsAllocateSuccess", binary.BigEndian.Uint16(resp[:2]) == AllocateResponse)
	t.Log("Payload Length", binary.BigEndian.Uint16(resp[2:]))
	t.Log("Magic Cookie", resp[4:8])
	t.Log("TransactionID", resp[8:20])
	t.Log("Attributes", resp[20:n], len(resp[20:n]))
}
