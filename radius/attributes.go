package radius

type Attribute int

// Attributes is the key-value pair of attributes in RFC2865.
type Attributes map[Attribute]string

// Radius attributes from RFC2865 and RFC2882.
const (
	UserName     Attribute = 1
	UserPassword           = 2
	CHAPPassword           = 3

	NASIPAddress = 4
	NASPort      = 5
	ServiceType  = 6

	FramedProtocol    = 7
	FramedIPAddress   = 8
	FramedIPNetmask   = 9
	FramedRouting     = 10
	FilterID          = 11
	FramedMTU         = 12
	FramedCompression = 13

	LoginIPHost  = 14
	LoginService = 15
	LoginTCPPort = 16

	ReplyMessage   = 18
	CallbackNumber = 19
	CallbackID     = 20

	FramedRoute      = 22
	FramedIPXNetwork = 23

	State              = 24
	Class              = 25
	VendorSpecific     = 26
	SessionTimeout     = 27
	IdleTimeout        = 28
	TerminiationAction = 29
	CalledStationID    = 30
	CallingStationID   = 31
	NASIdentifier      = 32
	ProxyState         = 33

	LoginLATService = 34
	LoginLATNode    = 35
	LoginLATGroup   = 36

	FramedAppleTalkLink    = 37
	FramedAppleTalkNetwork = 38
	FramedAppleTalkZone    = 39

	CHAPChallenge = 60
	NASPortType   = 61
	PortLimit     = 62
	LoginLATPort  = 63

	MessageAuthenticator = 80
)

var attrText = map[Attribute]string{
	UserName:     "User-Name",
	UserPassword: "User-Password",
	CHAPPassword: "CHAP-Password",

	NASIPAddress: "NAS-IP-Address",
	NASPort:      "NAS-Port",
	ServiceType:  "Service-Type",

	FramedProtocol:    "Framed-Protocol",
	FramedIPAddress:   "Framed-IP-Address",
	FramedIPNetmask:   "Framed-IP-Netmask",
	FramedRouting:     "Framed-Routing",
	FilterID:          "Filter-Id",
	FramedMTU:         "Framed-MTU",
	FramedCompression: "Framed-Compression",

	LoginIPHost:  "Login-IP-Host",
	LoginService: "Login-Service",
	LoginTCPPort: "Login-TCP-Port",

	ReplyMessage:   "Reply-Message",
	CallbackNumber: "Callback-Number",
	CallbackID:     "Callback-Id",

	FramedRoute:      "Framed-Route",
	FramedIPXNetwork: "Framed-IPX-Network",

	State:              "State",
	Class:              "Class",
	VendorSpecific:     "Vendor-Specific",
	SessionTimeout:     "Session-Timeout",
	IdleTimeout:        "Idle-Timeout",
	TerminiationAction: "Termination-Action",
	CalledStationID:    "Called-Station-Id",
	CallingStationID:   "Calling-Station-Id",
	NASIdentifier:      "NAS-Identifier",
	ProxyState:         "Proxy-State",

	LoginLATService: "Login-LAT-Service",
	LoginLATNode:    "Login-LAT-Node",
	LoginLATGroup:   "Login-LAT-Group",

	FramedAppleTalkLink:    "Framed-AppleTalk-Link",
	FramedAppleTalkNetwork: "Framed-AppleTalk-Network",
	FramedAppleTalkZone:    "Framed-AppleTalk-Zone",

	CHAPChallenge: "CHAP-Challenge",
	NASPortType:   "NAS-Port-Type",
	PortLimit:     "Port-Limit",
	LoginLATPort:  "Login-LAT-Port",
}

func (a Attribute) String() string {
	return attrText[a]
}

// Add adds a key-value pair to the list of attributes.
func (a Attributes) Add(key Attribute, value string) {
	a[key] = value
}
