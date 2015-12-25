package radius

import (
	"log"
	"net"
)

// Server based off RFC 2865 (RADIUS).
type Server struct {
	Net  string
	Addr string

	Conn  *net.UDPConn
	SAddr *net.UDPAddr

	// Secret is the shared secret used by the RADIUS server and clients.
	Secret string
}

type connection struct {
	message    []byte
	length     int
	server     *Server
	remoteAddr *net.UDPAddr
}

// HandlePacket takes a received UDP client and h
func (conn *connection) HandlePacket() {
	conn.Response(DecodePacket(conn.message, conn.length))
}

func (srv *Server) serve() (err error) {

	packetCount := 0

	for {
		clientConn := new(connection)
		clientConn.server = srv
		clientConn.message = make([]byte, 1024)

		// Wait for connection and then handle it in a new go routine.
		clientConn.length, clientConn.remoteAddr, err = srv.Conn.ReadFromUDP(clientConn.message[:])
		if err != nil {
			return err
		}
		go clientConn.HandlePacket()
		packetCount++
	}
}

func (srv *Server) ListenAndServe() (err error) {
	network := srv.Net
	addr := srv.Addr

	if network == "" {
		network = "udp"
	}
	if addr == "" {
		addr = ":1812"
	}

	srv.SAddr, err = net.ResolveUDPAddr(network, addr)
	if err != nil {
		return
	}

	srv.Conn, err = net.ListenUDP(network, srv.SAddr)
	if err != nil {
		return
	}

	defer srv.Conn.Close()

	return srv.serve()

}

// Response sends a UDP response using the ReceivedPacket to addr over the established UDP conn.
func (conn *connection) Response(ReceivedPacket Packet) {
	var err error

	var DecodedAttributes = ReceivedPacket.DecodedAttributes()

	if Authenticate(DecodedAttributes[UserName], DecodedAttributes[UserPassword]) {
		_, err = conn.server.Conn.WriteToUDP(PrepareAccessAccept(ReceivedPacket, conn.server.Secret), conn.remoteAddr)
	} else {
		_, err = conn.server.Conn.WriteToUDP(PrepareAccessReject(ReceivedPacket, conn.server.Secret), conn.remoteAddr)
	}

	if err != nil {
		log.Fatalln(err)
	}
}
