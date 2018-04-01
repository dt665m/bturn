package bturn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

var (
	TransactionID     = []byte{51, 64, 168, 147, 169, 188, 245, 134, 8, 87, 85, 52}
	FullTransactionID = []byte{33, 18, 164, 66, 51, 64, 168, 147, 169, 188, 245, 134, 8, 87, 85, 52}
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

	time.Sleep(1 * time.Second)
	ret := m.Run()
	time.Sleep(1 * time.Second)
	conn.Close()
	os.Exit(ret)
}

func TestPublicBindRequest(t *testing.T) {
	assertNil := assertNil(t)
	conn, err := net.Dial("udp", "stun.l.google.com:19302")
	if err != nil {
		t.Log(err)
		return
	}

	reqBuf := makeRequest(BindingRequest).Bytes()
	_, err = conn.Write(reqBuf)
	assertNil(err)

	resp := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	assertNil(err)

	t.Log("STUN Response", resp[:n])
	t.Log("Payload Length", binary.BigEndian.Uint16(resp[2:]))
	t.Log("Magic Cookie", resp[4:8])
	t.Log("TransactionID", resp[8:20])
	t.Log("Attributes", resp[20:n], len(resp[20:n]))

	attribs := ParseAttributes(resp[HeaderLength:n])
	addr, ok := GetAttribute(AttribXORMappedAddress, attribs).AsXorMappedAddress(FullTransactionID)
	if !ok {
		t.Error("unable to parse xormapped address")
	}
	fmt.Println("test:", []byte(addr.IP))
	fmt.Println("test:", addr.IP.String())
	fmt.Println("test:", isIPv4(addr.IP))
	//	XorAttribute  = []byte{0, 32, 0, 8, 0, 1, 213, 217, 253, 151, 244, 59}
}

func TestAllocateRequestFail(t *testing.T) {
	assertNil := assertNil(t)
	conn, err := net.Dial("udp", "127.0.0.1:8090")
	assertNil(err)

	reqBuf := makeRequest(AllocateRequest).Bytes()
	binary.BigEndian.PutUint16(reqBuf[2:4], uint16(len(reqBuf[HeaderLength:])))
	t.Log("STUN Request", reqBuf)
	t.Log("Magic Cookie", reqBuf[4:8])
	t.Log("TransactionID", reqBuf[8:20])
	t.Log("Attributes:", reqBuf[HeaderLength:])

	_, err = conn.Write(reqBuf)
	assertNil(err)

	resp := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	assertNil(err)

	//when parsing attributes, we have to check for "padded length" because length is encoded sans padding
	t.Log("STUN Response", resp[:n])
	t.Log("AllocateError", binary.BigEndian.Uint16(resp[:2]) == AllocateErrorResponse)
	t.Log("AllocateSuccess", binary.BigEndian.Uint16(resp[:2]) == AllocateResponse)
	t.Log("Payload Length", binary.BigEndian.Uint16(resp[2:]))
	t.Log("Magic Cookie", resp[4:8])
	t.Log("TransactionID", resp[8:20])
	t.Log("Attributes", resp[20:n], len(resp[20:n]))

	if binary.BigEndian.Uint16(resp[:2]) != AllocateErrorResponse {
		t.Errorf("allocate response error incorrect, expected %v, got %v", AllocateErrorResponse, binary.BigEndian.Uint16(resp[:2]))
	}
}

func TestAllocateRequestSuccess(t *testing.T) {
	assertNil := assertNil(t)
	conn, err := net.Dial("udp", "127.0.0.1:8090")
	assertNil(err)

	req := makeRequest(AllocateRequest)
	WriteRequestedTransport(req, UDPTransport)
	reqBuf := req.Bytes()
	binary.BigEndian.PutUint16(reqBuf[2:4], uint16(len(reqBuf[HeaderLength:])))
	t.Log("STUN Request", reqBuf)
	t.Log("Magic Cookie", reqBuf[4:8])
	t.Log("TransactionID", reqBuf[8:20])
	t.Log("Attributes:", reqBuf[HeaderLength:])

	_, err = conn.Write(reqBuf)
	assertNil(err)

	resp := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	assertNil(err)

	//when parsing attributes, we have to check for "padded length" because length is encoded sans padding
	t.Log("STUN Response", resp[:n])
	t.Log("IsAllocateError", binary.BigEndian.Uint16(resp[:2]) == AllocateErrorResponse)
	t.Log("IsAllocateSuccess", binary.BigEndian.Uint16(resp[:2]) == AllocateResponse)
	t.Log("Payload Length", binary.BigEndian.Uint16(resp[2:]))
	t.Log("Magic Cookie", resp[4:8])
	t.Log("TransactionID", resp[8:20])
	t.Log("Attributes", resp[20:n], len(resp[20:n]))

	if binary.BigEndian.Uint16(resp[:2]) != AllocateResponse {
		t.Errorf("allocate response incorrect, expected %v, got %v", AllocateResponse, binary.BigEndian.Uint16(resp[:2]))
	}
}

func TestChannelBind(t *testing.T) {
	assertNil := assertNil(t)
	wg := &sync.WaitGroup{}
	connA, err := net.Dial("udp", "127.0.0.1:8090")
	assertNil(err)

	connB, err := net.Dial("udp", "127.0.0.1:8090")
	assertNil(err)

	fmt.Println(connA.LocalAddr())
	fmt.Println(connB.LocalAddr())

	wg.Add(2)
	connHandler := func(conn net.Conn, otherAddr *net.UDPAddr) {
		defer wg.Done()
		req := makeRequest(AllocateRequest)
		WriteRequestedTransport(req, UDPTransport)
		reqBuf := req.Bytes()
		binary.BigEndian.PutUint16(reqBuf[2:4], uint16(len(reqBuf[HeaderLength:])))
		t.Log("STUN Request", reqBuf)
		t.Log("Magic Cookie", reqBuf[4:8])
		t.Log("TransactionID", reqBuf[8:20])
		t.Log("Attributes:", reqBuf[HeaderLength:])
		_, err = conn.Write(reqBuf)
		assertNil(err)

		resp := make([]byte, 1500)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err := conn.Read(resp)
		assertNil(err)
		if binary.BigEndian.Uint16(resp[:2]) != AllocateResponse {
			t.Errorf("allocate response incorrect, expected %v, got %v", AllocateResponse, binary.BigEndian.Uint16(resp[:2]))
		}
		req = makeRequest(ChannelBindRequest)
		WriteXorMappedAddress(req, otherAddr, FullTransactionID)
		WriteChannelNumber(req, RandChan())
		reqBuf = req.Bytes()
		binary.BigEndian.PutUint16(reqBuf[2:4], uint16(len(reqBuf[HeaderLength:])))
		t.Log("STUN Request", reqBuf)
		t.Log("Magic Cookie", reqBuf[4:8])
		t.Log("TransactionID", reqBuf[8:20])
		t.Log("Attributes:", reqBuf[HeaderLength:])

		_, err = conn.Write(reqBuf)
		assertNil(err)

		resp = make([]byte, 1500)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err = conn.Read(resp)
		assertNil(err)
		if binary.BigEndian.Uint16(resp[:2]) != ChannelBindResponse {
			t.Errorf("channelbind response incorrect, expected %v, got %v", ChannelBindResponse, binary.BigEndian.Uint16(resp[:2]))
		}
	}
	go connHandler(connA, connB.LocalAddr().(*net.UDPAddr))
	go connHandler(connB, connA.LocalAddr().(*net.UDPAddr))

	wg.Wait()
}

func makeRequest(reqType uint16) *bytes.Buffer {
	req := bytes.NewBuffer(make([]byte, 0, 512))
	binary.Write(req, binary.BigEndian, uint16(reqType))
	req.WriteByte(0) //pad zero length
	req.WriteByte(0)
	binary.Write(req, binary.BigEndian, uint32(MagicCookie))
	req.Write(TransactionID)
	return req
}

func assertNil(t *testing.T) func(v interface{}) {
	return func(v interface{}) {
		if v != nil {
			t.Fatal(v)
		}
	}
}

//get random channel port within ChannelBind Range
func RandChan() uint16 {
	rand.Seed(time.Now().Unix())
	min := int(ChannelDataStart)
	max := int(ChannelDataEnd)
	return uint16(rand.Intn(max-min) + min)
}
