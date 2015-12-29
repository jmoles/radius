package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"strings"
)

// Packet represents a RADIUS packet.
type Packet struct {
	Code          Code
	Identifier    int
	Length        int
	Authenticator [16]byte
	Attributes    []byte
}

// Equal compares two packets and returns true if they are the same.
func (packet *Packet) Equal(other Packet) bool {
	if packet.Code != other.Code {
		return false
	}
	if packet.Identifier != other.Identifier {
		return false
	}
	if packet.Length != other.Length {
		return false
	}
	if packet.Authenticator != other.Authenticator {
		return false
	}
	if packet.DecodedAttributes().Equal(other.DecodedAttributes()) != true {
		return false
	}

	return true
}

// DecodedAttributes returns the decoded set of Attributes.
func (packet *Packet) DecodedAttributes() Attributes {
	offset := 0

	var attr = make(Attributes, len(packet.Attributes)/3)

	for offset < len(packet.Attributes) {
		AttrType := Attribute(packet.Attributes[0+offset])
		AttrLen := uint8(packet.Attributes[1+offset])
		RawAttrVal := packet.Attributes[2+offset : int(AttrLen)+offset]

		attr[AttrType] = RawAttrVal

		offset += int(AttrLen)
	}

	return attr
}

// DecodePacket takes a received packet, packetIn, and ReceiveLength and returns a decoded version of the packet.
func DecodePacket(packetIn []byte, ReceiveLength int) (packet Packet) {

	packet.Code = Code(packetIn[0])
	packet.Identifier = int(binary.BigEndian.Uint16([]byte{0, packetIn[1]}))
	packet.Length = int(binary.BigEndian.Uint16([]byte{packetIn[2], packetIn[3]}))
	copy(packet.Authenticator[:], packetIn[4:20])
	packet.Attributes = packetIn[20:ReceiveLength]

	return
}

// updateLength updates the length field in the packet based off the fixed lengths from RFC and the length of the packet attributes.
func (packet *Packet) updateLength() {
	packet.Length = 1 + 1 + 2 + 16 + len(packet.Attributes)
}

func (packet *Packet) packetToBytes() []byte {
	buffer := new(bytes.Buffer)

	packet.updateLength()

	buffer.WriteByte(uint8(packet.Code))
	buffer.WriteByte(uint8(packet.Identifier))
	binary.Write(buffer, binary.BigEndian, uint16(packet.Length))
	binary.Write(buffer, binary.BigEndian, packet.Authenticator)
	binary.Write(buffer, binary.BigEndian, packet.Attributes)

	return buffer.Bytes()

}

// CalculateResponseAuthenticator takes the received packet, response length, and format of response to create a byte array
func CalculateResponseAuthenticator(rxPacket Packet, length int, format int, secret string) [16]byte {
	md5Buff := new(bytes.Buffer)

	md5Buff.WriteByte(uint8(format))
	md5Buff.WriteByte(uint8(rxPacket.Identifier))
	binary.Write(md5Buff, binary.BigEndian, uint16(length))
	binary.Write(md5Buff, binary.BigEndian, rxPacket.Authenticator)
	binary.Write(md5Buff, binary.BigEndian, rxPacket.Attributes)
	md5Buff.WriteString(secret)

	ReversePassword(rxPacket.DecodedAttributes()[UserPassword], rxPacket.Authenticator, secret)

	return md5.Sum(md5Buff.Bytes())
}

// PrepareAccessAccept takes a ReceivedPacket and builds an Access-Accept resp ready to pass to a UDP connection.
func PrepareAccessAccept(ReceivedPacket Packet, secret string) []byte {
	packet := new(Packet)

	packet.Code = AccessAccept
	packet.Identifier = ReceivedPacket.Identifier
	packet.updateLength()
	packet.Authenticator = CalculateResponseAuthenticator(ReceivedPacket, packet.Length, AccessAccept, secret)

	return packet.packetToBytes()
}

// PrepareAccessReject takes a ReceivedPacket and builds an Access-Reject resp ready to pass to a UDP connection.
func PrepareAccessReject(ReceivedPacket Packet, secret string) []byte {
	packet := new(Packet)

	packet.Code = AccessReject
	packet.Identifier = ReceivedPacket.Identifier
	packet.updateLength()
	packet.Authenticator = CalculateResponseAuthenticator(ReceivedPacket, packet.Length, AccessReject, secret)

	return packet.packetToBytes()
}

func ReversePassword(hiddenPassword []byte, authenticator [16]byte, secret string) string {

	offset := 0
	var password bytes.Buffer

	for offset < len(hiddenPassword) {
		var pN [16]byte
		var cN []byte
		var bN [16]byte

		if offset+16 > len(hiddenPassword) {
			cN = hiddenPassword[offset:]
			for len(cN) < 16 {
				cN = append(cN, 0x00)
			}
		} else {
			cN = hiddenPassword[offset : offset+16]
		}

		if offset == 0 {
			bN = md5.Sum(append([]byte(secret), authenticator[:]...))
		} else {
			bN = md5.Sum([]byte(secret + string(hiddenPassword[offset-16:offset])))
		}

		for i := 0; i < 16; i++ {
			pN[i] = bN[i] ^ cN[i]
		}

		password.Write(pN[:])

		offset += 16

	}

	return strings.Trim(password.String(), "\x00")
}
