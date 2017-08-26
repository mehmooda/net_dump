package loop_pcap

import "net"
import "encoding/binary"
import "time"
import "io"

type NetWrapper struct {
	net.Conn
	trace  *Looper
	bread  uint64
	bwrite uint64
}

func Wrap(a net.Conn, loop *Looper) *NetWrapper {
	w := &NetWrapper{Conn: a, trace: loop}
	w.writePacket(nil, true, 0x02)
	w.bwrite += 1
	w.writePacket(nil, false, 0x12)
	w.bread += 1
	w.writePacket(nil, true, 0x10)
	return w
}

func (w *NetWrapper) Read(b []byte) (n int, err error) {
	n, err = w.Conn.Read(b)
	if n != 0 {
		w.writePacket(b[:n], false, 0x18)
	}
	if err != nil {
		if err == io.EOF {
			w.writePacket(nil, false, 0x11)
		} else {
			w.writePacket([]byte(err.Error()), false, 0x04)
		}
	}
	w.bread += uint64(n)
	return n, err
}

func (w *NetWrapper) Write(b []byte) (n int, err error) {
	n, err = w.Conn.Write(b)
	if n != 0 {
		w.writePacket(b[:n], true, 0x18)
	}
	if err != nil {
		w.writePacket([]byte(err.Error()), false, 0x04)
	}

	w.bwrite += uint64(n)
	return n, err
}

func (w *NetWrapper) Close() (err error) {
	w.writePacket(nil, true, 0x11)
	err = w.Conn.Close()
	if err != nil {
		w.writePacket([]byte(err.Error()), false, 0x04)
	} else {
		w.writePacket(nil, false, 0x11)
	}
	return
}

func (w *NetWrapper) writePacket(b []byte, sent bool, flags byte) {
	l, ok := w.LocalAddr().(*net.TCPAddr)
	if !ok {
		panic(w.LocalAddr())
	}
	r, ok := w.RemoteAddr().(*net.TCPAddr)
	if !ok {
		panic(w.RemoteAddr())
	}
	lseq := w.bwrite
	rseq := w.bread
	if !sent {
		s := l
		l = r
		r = s
		ss := lseq
		lseq = rseq
		rseq = ss
	}
	cap_len := (len(b) + 43) / 4 * 4
	block_len := 28 + cap_len + 4
	output := make([]byte, block_len)
	//PACKET HEADER
	copy(output, packet_header)
	binary.LittleEndian.PutUint32(output[4:], uint32(block_len))
	t := time.Now().UnixNano() / 1000
	tlow := uint32(t)
	thigh := uint32(t >> 32)
	binary.LittleEndian.PutUint32(output[12:], thigh)
	binary.LittleEndian.PutUint32(output[16:], tlow)
	binary.LittleEndian.PutUint32(output[20:], uint32(len(b))+40)
	binary.LittleEndian.PutUint32(output[24:], uint32(len(b))+40)
	copy(output[28:], IPTCPheader)
	copy(output[40:], l.IP)
	copy(output[44:], r.IP)
	binary.BigEndian.PutUint16(output[48:], uint16(l.Port))
	binary.BigEndian.PutUint16(output[50:], uint16(r.Port))
	binary.BigEndian.PutUint32(output[52:], uint32(lseq))
	binary.BigEndian.PutUint32(output[56:], uint32(rseq))
	output[61] = flags
	copy(output[68:], b)
	binary.LittleEndian.PutUint32(output[28+cap_len:], uint32(block_len))
	w.trace.Lock()
	w.trace.Write(output)
	w.trace.Unlock()

}
