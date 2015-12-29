package radius

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"testing"
	"time"
)

const RA1 string = "\x0bl}RLDN\x11\xd39 \xc3j\x06\xf1}"
const RA2 string = "\x50\x20\x8c\x8d\x1f\x70\x15\xbf\xc1\x18\x42\x6a\x6c\xe6\x92\xec"
const secret string = "my_secret"
const packet string = "\x01\xac\x00\x4d\x50\x20\x8c\x8d\x1f\x70\x15\xbf\xc1\x18\x42\x6a\x6c\xe6\x92\xec\x01\x09\x65\x78\x61\x6d\x70\x6c\x65\x02\x12\x7e\x67\x02\x04\xef\xa0\x7b\x48\x1d\xf2\xc2\x4b\xf7\x25\xf1\x07\x04\x06\x7f\x00\x00\x01\x05\x06\x00\x00\x07\xcf\x50\x12\x33\x10\x58\x08\x06\xbb\x91\x1f\x43\xbe\x5c\x88\xd0\xa2\x59\x17"
const attr string = "01096578616d706c6502127e670204efa07b481df2c24bf725f10704067f0000010506000007cf50123310580806bb911f43be5c88d0a25917"
const identifier int = 172

func buildTestPacket(pType Code, ident int, requestAuth string, attributes string) Packet {

	var auth [16]byte
	copy(auth[:], []byte(requestAuth))

	rand.Seed(time.Now().Unix())

	attrBytes, _ := hex.DecodeString(attributes)

	lengthCalc := 1 + 1 + 2 + 16 + len(attrBytes)

	return Packet{
		pType,
		ident,
		lengthCalc,
		auth,
		attrBytes,
	}
}

func TestPacketEqual(t *testing.T) {
	var auth1, auth2 [16]byte
	copy(auth1[:], []byte(RA1))
	copy(auth2[:], []byte(RA2))

	cases := []struct {
		first    Packet
		second   Packet
		expected bool
	}{
		// Checking that something is indeed equal.
		{buildTestPacket(AccessRequest, identifier, RA1, attr),
			buildTestPacket(AccessRequest, identifier, RA1, attr),
			true},
		// Check failure on type, identifier, length, auth, and attributes.
		{buildTestPacket(AccessRequest, identifier, RA1, attr),
			buildTestPacket(AccessReject, identifier, RA1, attr),
			false},
		{buildTestPacket(AccessRequest, identifier, RA1, attr),
			buildTestPacket(AccessRequest, identifier+1, RA1, attr),
			false},
		{buildTestPacket(AccessRequest, identifier, RA1, attr+"aa"),
			buildTestPacket(AccessRequest, identifier, RA1, attr),
			false},
		{buildTestPacket(AccessRequest, identifier, RA1, attr),
			buildTestPacket(AccessRequest, identifier, RA2, attr),
			false},
		{buildTestPacket(AccessRequest, identifier, RA1, attr),
			buildTestPacket(AccessRequest, identifier, RA2, ""),
			false},
	}

	for test, c := range cases {
		got := c.first.Equal(c.second)

		if got != c.expected {
			t.Errorf("Test %d first.Equal(second) == %t, want %X", test, c.expected, got)
		}
	}
}

func TestDecodedAttributes(t *testing.T) {

	cases := []struct {
		packet   Packet
		expected Attributes
	}{
		{buildTestPacket(AccessRequest, identifier, RA1, attr),
			Attributes{UserName: []byte("example"),
				UserPassword:         []byte("\x7e\x67\x02\x04\xef\xa0\x7b\x48\x1d\xf2\xc2\x4b\xf7\x25\xf1\x07"),
				NASIPAddress:         []byte("\x7f\x00\x00\x01"),
				NASPort:              []byte("\x00\x00\x07\xcf"),
				MessageAuthenticator: []byte("\x33\x10\x58\x08\x06\xbb\x91\x1f\x43\xbe\x5c\x88\xd0\xa2\x59\x17")}},
		{buildTestPacket(AccessRequest, identifier, RA1, ""),
			make(Attributes)},
	}
	for test, c := range cases {
		got := c.packet.DecodedAttributes()

		if got.Equal(c.expected) != true {
			t.Errorf("Test %d c.packet.DecodedAttributes == %v, want %v", test, got, c.expected)
		}
	}

}

func TestDecodePacket(t *testing.T) {

	cases := []struct {
		bytes    []byte
		length   int
		expected Packet
	}{
		{[]byte(packet), buildTestPacket(AccessRequest, identifier, RA2, attr).Length, buildTestPacket(AccessRequest, identifier, RA2, attr)},
	}

	for test, c := range cases {
		got := DecodePacket(c.bytes, c.length)

		if c.expected.Equal(got) != true {
			t.Errorf("Test %d: DecodePacket(%X, %d) == %v, want %v", test, c.bytes, c.length, got, c.expected)
		}
	}
}

// TODO: Build test for updateLength

// TODO: Build test for packetToBytes

func TestCalculateResponseAuthenticator(t *testing.T) {

	attrBytes, _ := hex.DecodeString(attr)

	cases := []struct {
		testRXPacket Packet
		length       int
		format       int
		secret       string
		expected     []byte
	}{
		//RA=MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
		{buildTestPacket(AccessAccept, 154, RA1, attr),
			buildTestPacket(AccessAccept, 154, RA1, attr).Length, AccessAccept, secret,
			[]byte("\x02\x9A" + "\x00\x4D" + RA1 + string(attrBytes) + secret)},
		{buildTestPacket(AccessReject, 99, RA1, attr),
			buildTestPacket(AccessAccept, 154, RA1, attr).Length, AccessReject, secret,
			[]byte("\x03\x63" + "\x00\x4D" + RA1 + string(attrBytes) + secret)},
		{buildTestPacket(AccessChallenge, 21, RA1, attr),
			buildTestPacket(AccessAccept, 154, RA1, attr).Length, AccessChallenge, secret,
			[]byte("\x0B\x15" + "\x00\x4D" + RA1 + string(attrBytes) + secret)},
	}

	for test, c := range cases {
		got := CalculateResponseAuthenticator(c.testRXPacket, c.length, c.format, c.secret)

		if got != md5.Sum(c.expected) {
			t.Errorf("Test %d: CalculateResponseAuthenticator == %X, want %X", test, got, md5.Sum(c.expected))
		}
	}
}

// TODO: Add test for PrepareAccessAccept

// TODO: Add test for PrepareAccessReject

func TestReversePassword(t *testing.T) {

	var auth [16]byte
	copy(auth[:], []byte(RA1))

	cases := []struct {
		password string
		hidden   []byte
		auth     [16]byte
		secret   string
	}{
		{"loudyard", []byte("\xdb\xa1\xddtyS#J\xf0\xb9\xcdXT\x8f\xfer"), auth, secret},
		{"loud__yard__find__settle", []byte("\xdb\xa1\xddt_m(O\x82\xdd\x92\x072\xe6\x90\x16yx\xbe\x9f\xc3\x99\xed.*\x1c^L\xfa\xd7,\x0e"), auth, secret},
	}

	for _, c := range cases {
		got := ReversePassword(c.hidden, c.auth, c.secret)

		if got != c.password {
			t.Errorf("ReversePassword(%s) == %s, want %s", string(c.hidden), got, c.password)
		}
	}
}
