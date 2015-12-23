package radius

// Packet represents a RADIUS packet.
type Packet struct {
	Code          int
	Identifier    int
	Length        int
	Authenticator string
	Attributes    []byte
}

// DecodeAttributes takes a byte array of attributes from a received packet and returns a decoded set of attr.
func DecodeAttributes(attributes []byte) Attributes {
	offset := 0

	var attr = make(Attributes, len(attributes)/3)

	for offset < len(attributes) {
		AttrType := int(attributes[0+offset])
		AttrLen := uint8(attributes[1+offset])
		RawAttrVal := string(attributes[2+offset : int(AttrLen)+offset])

		attr[AttrType] = RawAttrVal

		offset += int(AttrLen)
	}

	return attr
}
