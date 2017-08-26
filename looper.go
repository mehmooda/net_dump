package loop_pcap

import "encoding/binary"
import "os"
import "sync"

type Looper struct {
	sync.Mutex
	data  []byte
	start int
	inuse int
}

func NewLooper(n int) *Looper {
	return &Looper{data: make([]byte, n)}
}

func (l *Looper) MakeSpace(n int) {
	total := len(l.data)
	for total-l.inuse < n {
		if l.inuse <= 0 {
			panic("CANT REMOVE ANYMORE")
		}
		this_packet := int(binary.LittleEndian.Uint32(l.data[(l.start+4)%total:]))
		l.start = (l.start + this_packet) % total
		l.inuse += -this_packet
	}
}

func (l *Looper) Write(b []byte) {
	to_write := len(b)
	l.MakeSpace(to_write)
	total := len(l.data)
	write_from := (l.start + l.inuse) % total
	written := copy(l.data[write_from:], b)
	if written < to_write {
		copy(l.data, b[written:])
	}
	l.inuse += to_write
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func (l *Looper) DumpToDisk() {
	l.Lock()
	defer l.Unlock()
	f, err := os.Create("/tmp/dat2")
	check(err)

	defer f.Close()

	f.Write(shb_header)
	f.Write(interface_desc)
	if l.start+l.inuse > len(l.data) {
		f.Write(l.data[l.start:])
		f.Write(l.data[:l.start-(len(l.data)-l.inuse)])
	} else {
		f.Write(l.data[l.start : l.start+l.inuse])
	}
}
