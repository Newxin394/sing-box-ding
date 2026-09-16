package interrupt

import (
	"net"
	"os"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

type Conn struct {
	net.Conn
	group   *Group
	element *list.Element[*groupConnItem]
}

func (c *Conn) Close() error {
	c.group.access.Lock()
	defer c.group.access.Unlock()
	c.group.connections.Remove(c.element)
	return c.Conn.Close()
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return true
}

func (c *Conn) Upstream() any {
	return c.Conn
}

type PacketConn struct {
	N.NetPacketConn
	group   *Group
	element *list.Element[*groupConnItem]
}

func newPacketConn(group *Group, conn net.PacketConn, element *list.Element[*groupConnItem]) *PacketConn {
	return &PacketConn{NetPacketConn: bufio.NewPacketConn(conn), group: group, element: element}
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if packetReader, ok := c.NetPacketConn.(N.PacketReader); ok {
		return packetReader.ReadPacket(buffer)
	}
	packetConn, isPacketConn := c.NetPacketConn.(net.PacketConn)
	if !isPacketConn {
		return M.Socksaddr{}, os.ErrInvalid
	}
	_, addr, err := buffer.ReadPacketFrom(packetConn)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.SocksaddrFromNet(addr).Unwrap(), err
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if packetWriter, ok := c.NetPacketConn.(N.PacketWriter); ok {
		return packetWriter.WritePacket(buffer, destination)
	}
	packetConn, isPacketConn := c.NetPacketConn.(net.PacketConn)
	if !isPacketConn {
		buffer.Release()
		return os.ErrInvalid
	}
	defer buffer.Release()
	_, err := packetConn.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}

func (c *PacketConn) Close() error {
	c.group.access.Lock()
	defer c.group.access.Unlock()
	c.group.connections.Remove(c.element)
	return c.NetPacketConn.Close()
}

func (c *PacketConn) ReaderReplaceable() bool {
	return true
}

func (c *PacketConn) WriterReplaceable() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return c.NetPacketConn
}
