package radius

// Radius packet codes from RFC 2865
const (
	AccessRequest = 1
	AccessAccept  = 2
	AccessReject  = 3

	AccountingRequest  = 4
	AccountingResponse = 5
	AccountingStatus   = 6

	PasswordRequest = 7
	PasswordAck     = 8
	PasswordReject  = 9

	AccountingMessage = 10
	AccessChallenge   = 11

	StatusServer = 12
	StatusClient = 13

	ResourceFreeRequest   = 21
	ResourceFreeResponse  = 22
	ResourceQueryRequest  = 23
	ResourceQueryResponse = 24

	AlternativeResourceRelacimRequest = 25

	NASRebootRequest  = 26
	NASRebootResponse = 27

	NextPasscode     = 29
	NewPin           = 30
	TerminateSession = 31
	PasswordExpired  = 32

	EventRequest  = 33
	EventResponse = 34

	DisconnectRequest = 40
	DisconnectACK     = 41
	DisconnectNAK     = 42

	CoARequest = 43
	CoAACK     = 44
	CoANAK     = 45

	IPAddressAllocate = 50
	IPAddressRelese   = 51
)

var codeText = map[int]string{
	AccessRequest: "Access-Request",
	AccessAccept:  "Access-Accept",
	AccessReject:  "Access-Reject",

	AccountingRequest:  "Accounting-Request",
	AccountingResponse: "Accounting-Response",
	AccountingStatus:   "Accounting-Status",

	PasswordRequest: "Password-Request",
	PasswordAck:     "Password-Ack",
	PasswordReject:  "Password-Reject",

	AccountingMessage: "Accounting-Message",
	AccessChallenge:   "Access-Challenge",

	StatusServer: "Status-Server",
	StatusClient: "Status-Client",

	ResourceFreeRequest:   "Resource-Free-Request",
	ResourceFreeResponse:  "Resource-Free-Response",
	ResourceQueryRequest:  "Resource-Query-Request",
	ResourceQueryResponse: "Resource-Query-Response",

	AlternativeResourceRelacimRequest: "Alternate-Resource-Reclaim-Request",

	NASRebootRequest:  "NAS-Reboot-Request",
	NASRebootResponse: "NAS-Reboot-Response",

	NextPasscode:     "Next-Passcode",
	NewPin:           "New-Pin",
	TerminateSession: "Terminate-Session",
	PasswordExpired:  "Password-Expired",

	EventRequest:  "Event-Request",
	EventResponse: "Event-Response",

	DisconnectRequest: "Disconnect-Request",
	DisconnectACK:     "Disconnect-ACK",
	DisconnectNAK:     "Disconnect-NAK",

	CoARequest: "CoA-Request",
	CoAACK:     "CoA-ACK",
	CoANAK:     "CoA-NAK",

	IPAddressAllocate: "IP-Address-Allocate",
	IPAddressRelese:   "IP-Address-Release",
}
