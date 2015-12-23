package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"log"
	"net"

	"github.com/jmoles/radius/radius"
)

// Secret is a temporary variable with the shared secret between the server.
const Secret string = "testsecret"

// Authenticate determines to authenticate a user or not.
func Authenticate(user string, password string) (authenticated bool) {
	if user == "example" {
		return true
	}

	return false

}

// PrepareResponseAuthenticator takes the received packet, response length, and format of response to create a byte array
func PrepareResponseAuthenticator(packet radius.Packet, length int, format int) (md5Sum [16]byte) {
	md5Buff := new(bytes.Buffer)

	md5Buff.WriteByte(uint8(format))
	md5Buff.WriteByte(uint8(packet.Identifier))
	binary.Write(md5Buff, binary.BigEndian, uint16(length))
	md5Buff.WriteString(packet.Authenticator)
	md5Buff.WriteString(Secret)

	md5Sum = md5.Sum(md5Buff.Bytes())

	return
}

// PrepareAccessAccept takes a ReceivedPacket and builds an Access-Accept resp ready to pass to a UDP connection.
func PrepareAccessAccept(ReceivedPacket radius.Packet) (resp []byte) {
	respBuffer := new(bytes.Buffer)

	// Write the code, identifier, length, response authenticator, and attributes.
	respBuffer.WriteByte(radius.AccessAccept)
	respBuffer.WriteByte(uint8(ReceivedPacket.Identifier))
	binary.Write(respBuffer, binary.BigEndian, uint16(1+1+2+16))
	binary.Write(respBuffer, binary.BigEndian, PrepareResponseAuthenticator(ReceivedPacket, 20, radius.AccessAccept))

	resp = respBuffer.Bytes()

	return
}

// PrepareAccessReject takes a ReceivedPacket and builds an Access-Reject resp ready to pass to a UDP connection.
func PrepareAccessReject(packet radius.Packet) (resp []byte) {
	respBuffer := new(bytes.Buffer)

	// Write the code, identifier, length, response authenticator, and attributes.
	respBuffer.WriteByte(radius.AccessReject)
	respBuffer.WriteByte(uint8(packet.Identifier))
	binary.Write(respBuffer, binary.BigEndian, uint16(1+1+2+16))
	binary.Write(respBuffer, binary.BigEndian, PrepareResponseAuthenticator(packet, 20, radius.AccessReject))

	resp = respBuffer.Bytes()

	return
}

// RadiusResponse sends a UDP response using the ReceivedPacket to addr over the established UDP conn.
func RadiusResponse(ReceivedPacket radius.Packet, addr *net.UDPAddr, conn *net.UDPConn) {
	var err error

	var DecodedAttributes = radius.DecodeAttributes(ReceivedPacket.Attributes)

	if Authenticate(DecodedAttributes[radius.UserName], DecodedAttributes[radius.UserPassword]) {
		_, err = conn.WriteToUDP(PrepareAccessAccept(ReceivedPacket), addr)
	} else {
		_, err = conn.WriteToUDP(PrepareAccessReject(ReceivedPacket), addr)
	}

	if err != nil {
		log.Fatalln(err)
	}
}

// HandlePacket takes a received UDP buf with given ReceiveLength and PacketCount from addr over UDP conn.
func HandlePacket(buf []byte, ReceiveLength int, PacketCount int, addr *net.UDPAddr, conn *net.UDPConn) {
	var dcpacket radius.Packet
	dcpacket = DecodePacket(buf, ReceiveLength)
	RadiusResponse(dcpacket, addr, conn)
}

// DecodePacket takes a received packet and ReceiveLength and returns a decoded version of the packet, DCPacket.
func DecodePacket(packet []byte, ReceiveLength int) (DCPacket radius.Packet) {

	DCPacket.Code = int(packet[0])
	DCPacket.Identifier = int(binary.BigEndian.Uint16([]byte{0, packet[1]}))
	DCPacket.Length = int(binary.BigEndian.Uint16([]byte{packet[2], packet[3]}))
	DCPacket.Authenticator = string(packet[4:20])
	DCPacket.Attributes = packet[20:ReceiveLength]

	return
}

func main() {
	sAddr, err := net.ResolveUDPAddr("udp", ":1812")
	if err != nil {
		log.Fatalln(err)
	}
	sock, err := net.ListenUDP("udp", sAddr)
	if err != nil {
		log.Fatalln(err)
	}
	defer sock.Close()
	packetCount := 0
	for {
		buf := make([]byte, 1024)

		// Wait for a connection.
		rlen, addr, err := sock.ReadFromUDP(buf[:])
		if err != nil {
			log.Fatal(err)
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go HandlePacket(buf, rlen, packetCount, addr, sock)
		packetCount++
	}
}
