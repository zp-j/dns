package dns

import "net"

// Pack and unpack functions for messages.

func errPack(tag string) error   { return &Error{err: "overflow packing `" + tag + "'"} }
func errUnpack(tag string) error { return &Error{err: "overflow unpacking `" + tag + "'"} }

func unpackTagA(msg []byte, off int) (net.IP, int, error) {
	lenmsg := len(msg)
	if off == lenmsg {
		return nil, off, nil // dynamic updates
	}
	if off+net.IPv4len > lenmsg {
		return nil, lenmsg, errUnpack("a")
	}
	a := net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3])
	off += net.IPv4len
	return a, off, nil
}

func packTagA(a net.IP, msg []byte, off int) (int, error) {
	lenmsg := len(msg)
	if off+net.IPv4len > lenmsg {
		return lenmsg, errPack("a")
	}
	switch len(a) {
	case net.IPv6len:
		msg[off] = a[12]
		msg[off+1] = a[13]
		msg[off+2] = a[14]
		msg[off+3] = a[15]
		off += net.IPv4len
	case net.IPv4len:
		msg[off] = a[0]
		msg[off+1] = a[1]
		msg[off+2] = a[2]
		msg[off+3] = a[3]
		off += net.IPv4len
	case 0:
		// Allowed, for dynamic updates
	default:
		return lenmsg, errPack("a")
	}
	return off, nil
}

func unpackTagAAAA(msg []byte, off int) (net.IP, int, error) {
	lenmsg := len(msg)
	if off == lenmsg {
		return nil, off, nil // dynamic updates
	}
	if off+net.IPv6len > lenmsg {
		return nil, lenmsg, errUnpack("aaaa")
	}
	aaaa := net.IP{msg[off], msg[off+1], msg[off+2], msg[off+3], msg[off+4],
		msg[off+5], msg[off+6], msg[off+7], msg[off+8], msg[off+9], msg[off+10],
		msg[off+11], msg[off+12], msg[off+13], msg[off+14], msg[off+15]}
	off += net.IPv6len
	return aaaa, off, nil
}

func packTagAAAA(aaaa net.IP, msg []byte, off int) (int, error) {
	lenmsg := len(msg)
	if off+net.IPv6len > lenmsg {
		return lenmsg, errPack("aaaa")
	}
	switch len(aaaa) {
	case net.IPv6len:
		for i := 0; i < net.IPv6len; i++ {
			msg[off] = aaaa[i]
			off++
		}
	case 0:
		// Allowed, for dynamic updates
	default:
		return lenmsg, errPack("aaaa")
	}
	return off, nil
}
