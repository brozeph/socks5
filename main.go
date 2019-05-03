package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	rfc1928AtypDomanName                  = 0x03 // rfc1928 = no auth
	rfc1928AtypIPv4                       = 0x01
	rfc1928AtypIPv4Length                 = 4
	rfc1928AtypIPv6                       = 0x04
	rfc1928AtypIPv6Length                 = 16
	rfc1928CommandBind                    = 0x02
	rfc1928CommandConnect                 = 0x01
	rfc1928CommandUDPAssociate            = 0x03
	rfc1928MethodGSSAPI                   = 0x01
	rfc1928MethodNoAcceptableMethods      = 0xff
	rfc1928MethodNoAuthenticationRequired = 0x00
	rfc1928MethodUsernamePassword         = 0x02
	rfc1928ReplyAddressTypeNotSupported   = 0x08
	rfc1928ReplyGeneralFailure            = 0x01
	rfc1928ReplyGeneralSuccess            = 0x00
	rfc1928Version                        = 0x05
	rfc1929ReplyGeneralFailure            = 0xff // rfc1929 = basic auth
	rfc1929ReplyGeneralSuccess            = 0x00
	rfc1929Version                        = 0x01
)

func checkVersion(ver byte) error {
	if ver != rfc1928Version {
		return errors.New("version mismatch detected")
	}

	return nil
}

func connect(c net.Conn) {
	req := make([]byte, 4)

	// The request is formed by the SOCKS5 client as follows...
	//
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	if _, err := c.Read(req); err != nil {
		log.Println(err)
		endConnection(c, []byte{rfc1928Version, rfc1928ReplyGeneralFailure})
		return
	}

	ver := req[0]
	cmd := req[1]
	atyp := req[3]

	if err := checkVersion(ver); err != nil {
		log.Println(err)
		endConnection(c, []byte{rfc1928Version, rfc1928ReplyGeneralFailure})
		return
	}

	log.Printf("VER %d, CMD %d, ATYP %d\n", ver, cmd, atyp)

	// prepare acknowledgement while processing request
	ack := make([]byte, 4)
	ack[0] = rfc1928Version
	ack[1] = rfc1928ReplyGeneralSuccess
	ack[2] = 0x00
	ack[3] = atyp

	var addr = ""

	// TODO: track active sessions

	// detect destination address
	switch atyp {
	case rfc1928AtypDomanName:
		size := make([]byte, 1)
		if _, err := c.Read(size); err != nil {
			log.Println(err)
			endConnection(c, []byte{rfc1928Version, rfc1928ReplyGeneralFailure})
			return
		}

		ack = append(ack, size[0])

		dst := make([]byte, size[0])
		if _, err := c.Read(dst); err != nil {
			log.Println(err)
			endConnection(c, []byte{rfc1928Version, rfc1928ReplyGeneralFailure})
			return
		}

		addr = string(dst[:size[0]])
		for _, b := range dst {
			ack = append(ack, b)
		}

	case rfc1928AtypIPv4:
		dst := make([]byte, rfc1928AtypIPv4Length)
		if _, err := c.Read(dst); err != nil {
			log.Println(err)
			endConnection(c, []byte{rfc1928Version, rfc1928ReplyGeneralFailure})
			return
		}

		addr = fmt.Sprintf("%d.%d.%d.%d", dst[0], dst[1], dst[2], dst[3])
		for _, b := range dst {
			ack = append(ack, b)
		}

	case rfc1928AtypIPv6:
		dwords := [][]byte{
			make([]byte, 4),
			make([]byte, 4),
			make([]byte, 4),
			make([]byte, 4),
		}

		for _, b := range dwords {
			if _, err := c.Read(b); err != nil {
				log.Println(err)
				endConnection(c, []byte{rfc1928Version, rfc1928ReplyGeneralFailure})
				return
			}

			// build addrSlice
			for _, v := range b {
				ack = append(ack, v)
			}
		}

		// dword A - D - convert byte strings to unsigned BE int32
		dwordA := binary.BigEndian.Uint32(dwords[0])
		dwordB := binary.BigEndian.Uint32(dwords[1])
		dwordC := binary.BigEndian.Uint32(dwords[2])
		dwordD := binary.BigEndian.Uint32(dwords[3])

		// convert each DWORD (uint32) into 2 WORD (uint16) values
		// and string format each value as base 16 with a colon delimeter
		addr = fmt.Sprintf(
			"%s:%s:%s:%s:%s:%s:%s:%s",
			strconv.FormatUint(uint64(dwordA&0xffff0000), 16),
			strconv.FormatUint(uint64(dwordA&0xffff), 16),
			strconv.FormatUint(uint64(dwordB&0xffff0000>>16), 16),
			strconv.FormatUint(uint64(dwordB&0xffff), 16),
			strconv.FormatUint(uint64(dwordC&0xffff0000>>16), 16),
			strconv.FormatUint(uint64(dwordC&0xffff), 16),
			strconv.FormatUint(uint64(dwordD&0xffff0000>>16), 16),
			strconv.FormatUint(uint64(dwordD&0xffff), 16))

	default:
		// TODO: handle or send out error
		log.Println("unable to detect ATYP")
		ack[1] = rfc1928ReplyAddressTypeNotSupported
		endConnection(c, ack)
		return
	}

	// detect destination port
	p := make([]byte, 2)
	if _, err := c.Read(p); err != nil {
		log.Println(err)
		ack[1] = rfc1928ReplyGeneralFailure
		endConnection(c, ack)
		return
	}

	// add port bytes to addrSlice
	for _, b := range p {
		ack = append(ack, b)
	}

	port := binary.BigEndian.Uint16(p)

	if cmd != rfc1928CommandConnect {
		// bind and udp associate SOCKS5 commands
		log.Println("bind or udp associate command detected")
		ack[1] = rfc1928ReplyGeneralFailure
		endConnection(c, ack)
		return
	}

	network, ip := parseAddress(addr)

	log.Printf("establishing %s connection to destination: %s:%d\n", network, ip, port)

	// TODO: parameterize timeout
	dst, err := net.DialTimeout(network, fmt.Sprintf("%s:%d", ip.String(), port), 10*time.Second)
	if err != nil {
		log.Println(err)
		// TODO: update ack to indicate real error...
		// X'03' Network unreachable
		// X'04' Host unreachable
		// X'05' Connection refused
		ack[1] = 0x03
		endConnection(c, ack)
		return
	}

	log.Printf("established %s connection to %s\n", dst.RemoteAddr().Network(), dst.RemoteAddr().String())

	// write ack to client (success)
	/*
		+----+-----+-------+------+----------+----------+
		|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	*/
	log.Println("sending ack to SOCKS5 client")
	c.Write(ack)

	// pipe data back and forth...
	go transfer(dst, c)
	go transfer(c, dst)
}

func endConnection(c net.Conn, ack []byte) {
	c.Write(ack)

	err := c.Close()
	if err != nil {
		log.Println("endConnection: unhandled error")
		log.Println(err)
		return
	}
}

func handshake(c net.Conn) {
	log.Printf("new connection from %s\n", c.RemoteAddr().String())

	// Socks5 proxy implementation. See RFC 1928 and 1929.
	//
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	b := make([]byte, 2)
	if _, err := c.Read(b); err != nil {
		log.Println(err)
		endConnection(c, []byte{rfc1928Version, rfc1928MethodNoAcceptableMethods})
		return
	}

	// verify version
	if err := checkVersion(b[0]); err != nil {
		log.Println(err)
		endConnection(c, []byte{rfc1928Version, rfc1928ReplyGeneralFailure})
		return
	}

	log.Printf("number of method identifier octets (bits) specified %d\n", b[1])

	// retrieve supported methods
	m := make([]byte, b[1])
	if _, err := c.Read(m); err != nil {
		log.Println(err)
		endConnection(c, []byte{rfc1928Version, rfc1928ReplyGeneralFailure})
		return
	}

	// TODO: check for basic auth configuration...
	// for now, responding with no authentication required

	// The server selects from one of the methods given in METHODS, and
	// sends a METHOD selection message:
	//
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |

	c.Write([]byte{rfc1928Version, rfc1928MethodNoAuthenticationRequired})

	go connect(c)
}

func main() {
	a := os.Args

	if len(a) == 1 {
		log.Println("port number is required")
		return
	}

	PORT := ":" + a[1]
	l, err := net.Listen("tcp", PORT)
	if err != nil {
		log.Println(err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			log.Println(err)
			return
		}
		go handshake(c)
	}
}

func parseAddress(addr string) (string, net.IP) {
	log.Printf("parsing destination address %s\n", addr)

	network := "tcp"
	ip := net.ParseIP(addr)
	if ip.To4() == nil {
		network = "tcp6"
	}

	return network, ip
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()

	w, err := io.Copy(dst, src)
	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("%d bytes written from destination to source\n", w)
}
