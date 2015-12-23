package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

// RadiusFormat represents an octect.
type RadiusFormat uint8

// RadiusAttribute represents an octet.
type RadiusAttribute uint8

// Constants describing the different type of RADIUS Code Requests.
const (
	AccessRequest      RadiusFormat = 1
	AccessAccept                    = 2
	AccessReject                    = 3
	AccountingRequest               = 4
	AccountingResponse              = 5
	AccessChallenge                 = 11
	StatusServer                    = 12
	StatusClient                    = 13
	Reserved                        = 255
)

// Constants describing the different radius attributes.
const (
	AttrUserName             RadiusAttribute = 1
	AttrUserPassword                         = 2
	AttrCHAPPassword                         = 3
	AttrNASIPAddress                         = 4
	AttrNASPort                              = 5
	AttrServiceType                          = 6
	AttrState                                = 24
	AttrMessageAuthenticator                 = 80
)

const Secret string = "testsecret"

// Packet represents a decoded RADIUS packet represented in RFC2865.
type DecodedPacket struct {
	code          RadiusFormat
	identifier    uint8
	length        uint16
	authenticator string
	attributes    Attributes
	attributesRaw string
}

// Attributes represents a set of RADIUS attributes defined in RFC2865.
type Attributes struct {
	UserName             string
	UserPassword         string
	ChapIdent            uint8
	ChapString           string
	NASIPAddress         net.IP
	NASPort              uint16
	ServiceType          uint32
	FramedProtocol       uint32
	FramedIPAddress      net.IP
	FramedIPNetmask      net.IP
	FramedRouting        uint32
	FilterID             string
	State                string
	MessageAuthenticator string
}

func RadiusResponse(packet DecodedPacket, addr *net.UDPAddr, conn *net.UDPConn) {
	// Calculate the MD5 Sum response.
	// Code+ID+Length+RequestAuth+Attributes+Secret)
	var err error
	var num int
	// var HexResult []byte

	md5resp := new(bytes.Buffer)
	resp := new(bytes.Buffer)

	md5resp.WriteByte(AccessAccept)
	md5resp.WriteByte(packet.identifier)
	binary.Write(md5resp, binary.BigEndian, uint16(20))
	md5resp.WriteString(packet.authenticator)
	md5resp.WriteString(Secret)

	resp.WriteByte(AccessAccept)
	resp.WriteByte(packet.identifier)
	binary.Write(resp, binary.BigEndian, uint16(20))
	binary.Write(resp, binary.BigEndian, md5.Sum(md5resp.Bytes()))

	fmt.Printf("MD5 Resp: %x\n", md5resp.Bytes())
	fmt.Printf("Resp: %x\n", resp.Bytes())

	num, err = conn.WriteToUDP(resp.Bytes(), addr)
	fmt.Printf("Number of Packets: %d\n", num)
	if err != nil {
		log.Fatalln(err)
	}
}

func handlePacket(buf []byte, rlen int, count int, addr *net.UDPAddr, conn *net.UDPConn) {
	var dcpacket DecodedPacket
	dcpacket = DecodePacket(buf, rlen)
	RadiusResponse(dcpacket, addr, conn)
}

func DecodeAttributes(attributes []byte) (attr Attributes) {
	offset := 0

	for offset < len(attributes) {
		AttrType := RadiusAttribute(attributes[0+offset])
		AttrLen := uint8(attributes[1+offset])

		RawAttrVal := attributes[2+offset : int(AttrLen)+offset]

		if AttrType == AttrUserName {
			attr.UserName = string(RawAttrVal)
		} else if AttrType == AttrUserPassword {
			attr.UserPassword = string(RawAttrVal)
		} else if AttrType == AttrCHAPPassword {
			attr.ChapIdent = uint8(RawAttrVal[0])
			attr.ChapString = string(RawAttrVal[1:])
		} else if AttrType == AttrNASIPAddress {
			attr.NASIPAddress = net.IPv4(RawAttrVal[0], RawAttrVal[1], RawAttrVal[2], RawAttrVal[3])
		} else if AttrType == AttrNASPort {
			attr.NASPort = uint16(binary.BigEndian.Uint32(RawAttrVal))
		} else if AttrType == AttrServiceType {
			attr.ServiceType = binary.BigEndian.Uint32(RawAttrVal)
		} else if AttrType == AttrState {
			attr.State = string(RawAttrVal)
		} else if AttrType == AttrMessageAuthenticator {
			attr.MessageAuthenticator = string(RawAttrVal)
		} else {
			fmt.Print("Not Found Type\n")
			fmt.Printf("Type: %d\n", AttrType)
			fmt.Printf("Length: %d\n", AttrLen)
		}

		offset += int(AttrLen)

	}

	return
}

func DecodePacket(packet []byte, rlen int) (DCPacket DecodedPacket) {

	DCPacket.code = RadiusFormat(packet[0])
	DCPacket.identifier = uint8(binary.BigEndian.Uint16([]byte{0, packet[1]}))
	DCPacket.length = binary.BigEndian.Uint16([]byte{packet[2], packet[3]})
	DCPacket.authenticator = string(packet[4:20])
	DCPacket.attributes = DecodeAttributes(packet[20:rlen])
	DCPacket.attributesRaw = string(packet[20:rlen])

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
		go handlePacket(buf, rlen, packetCount, addr, sock)
		packetCount++
	}
}
