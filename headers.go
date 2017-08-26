package loop_pcap

// Block
// offset  size    name            value
// 0       4       type
// 4       4       blocklength
// len-4   4       blocklength

// Section Header
// type = 0x0A0D0D0A
// offset  size    name            value
// 8       4       byteorder       0x1A2B3C4D
// 12      2       major           1
// 14      2       minor           0
// 16      8       sectionlength
// 24	   24      options
var shb_header = []byte{0x0A, 0x0D, 0x0D, 0x0A, 48, 0, 0, 0,
	0x4D, 0x3C, 0x2B, 0x1A, 0x01, 0, 0, 0,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	4, 0, 10, 0, 'G', 'O', ' ', 'N',
	'E', 'T', 'D', 'U', 'M', 'P', 0, 0,
	0, 0, 0, 0, 48, 0, 0, 0,
}

// Interface Description
// type = 1
// offset  size    name            value
// 8       2       linktype        101 Raw IP
// 10      2       reserved
// 12      4       options
var interface_desc = []byte{1, 0, 0, 0, 20, 0, 0, 0,
	101, 0, 0, 0, 0, 0, 0, 0,
	20, 0, 0, 0,
}

// Enhanced Packet Block
// type = 6
// offset  size    name            value
// 8       4       interface_id    0
// 12      8	   timestamp
// 20      4       caplen
// 24      4       plen
// 28      caplen  pdata           (caplen rounded up to 4)
//
var packet_header = []byte{6, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0}

var IPTCPheader = []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 0x40, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x18, 0x20, 0, 0, 0, 0, 0}

// Name Resolution Block
// type = 4
// offset  size    name            value
// 8       2       record type
// 10      2       record len
// 12      rlen
// TODO: COMPLETE
