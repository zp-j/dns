// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS packet assembly, see RFC 1035. Converting from - Unpack() -
// and to - Pack() - wire format.
// All the packers and unpackers take a (msg []byte, off int)
// and return (off1 int, ok bool).  If they return ok==false, they
// also return off1==len(msg), so that the next unpacker will
// also fail.  This lets us avoid checks of ok until the end of a
// packing sequence.

package dns

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"net"
	"strconv"
	"time"
)

const maxCompressionOffset = 2 << 13 // We have 14 bits for the compression pointer

var (
	ErrFqdn        error = &Error{Err: "dns: name must be fully qualified"}
	ErrId          error = &Error{Err: "dns: id mismatch"}
	ErrTag         error = &Error{Err: "dns: unknown tag"}
	ErrFmt         error = &Error{Err: "dns: illegal RR format"}
	ErrBuf         error = &Error{Err: "dns: buffer size too large"}
	ErrShortBuf    error = &Error{Err: "dns: buffer size too small"}
	ErrShortRead   error = &Error{Err: "dns: short read"}
	ErrLoop        error = &Error{Err: "dns: too many message pointers"}
	ErrBit         error = &Error{Err: "dns: illegal bits in message"}
	ErrConn        error = &Error{Err: "dns: conn holds both UDP and TCP connection"}
	ErrConnEmpty   error = &Error{Err: "dns: conn has no connection"}
	ErrServ        error = &Error{Err: "dns: no servers could be reached"}
	ErrKey         error = &Error{Err: "dns: bad key"}
	ErrPrivKey     error = &Error{Err: "dns: bad private key"}
	ErrKeySize     error = &Error{Err: "dns: bad key size"}
	ErrKeyAlg      error = &Error{Err: "dns: bad key algorithm"}
	ErrAlg         error = &Error{Err: "dns: bad algorithm"}
	ErrTime        error = &Error{Err: "dns: bad time"}
	ErrNoSig       error = &Error{Err: "dns: no signature found"}
	ErrSig         error = &Error{Err: "dns: bad signature"}
	ErrSecret      error = &Error{Err: "dns: no secrets defined"}
	ErrSigGen      error = &Error{Err: "dns: bad signature generation"}
	ErrAuth        error = &Error{Err: "dns: bad authentication"}
	ErrSoa         error = &Error{Err: "dns: no SOA"}
	ErrHandle      error = &Error{Err: "dns: handle is nil"}
	ErrChan        error = &Error{Err: "dns: channel is nil"}
	ErrName        error = &Error{Err: "dns: type not found for name"}
	ErrRRset       error = &Error{Err: "dns: invalid rrset"}
	ErrDenialNsec3 error = &Error{Err: "dns: no NSEC3 records"}
	ErrDenialCe    error = &Error{Err: "dns: no matching closest encloser found"}
	ErrDenialNc    error = &Error{Err: "dns: no covering NSEC3 found for next closer"}
	ErrDenialSo    error = &Error{Err: "dns: no covering NSEC3 found for source of synthesis"}
	ErrDenialBit   error = &Error{Err: "dns: type not denied in NSEC3 bitmap"}
	ErrDenialWc    error = &Error{Err: "dns: wildcard exist, but closest encloser is denied"}
	ErrDenialHdr   error = &Error{Err: "dns: message rcode conflicts with message content"}
)

// A manually-unpacked version of (id, bits).
// This is in its own struct for easy printing.
type MsgHdr struct {
	Id                 uint16
	Response           bool
	Opcode             int
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Rcode              int
}

// The layout of a DNS message.
type Msg struct {
	MsgHdr
	Compress bool       // If true, the message will be compressed when converted to wire format.
	Size     int        // Number of octects in the message received from the wire.
	Question []Question // Holds the RR(s) of the question section.
	Answer   []RR       // Holds the RR(s) of the answer section.
	Ns       []RR       // Holds the RR(s) of the authority section.
	Extra    []RR       // Holds the RR(s) of the additional section.
}

// Map of strings for each RR wire type.
var Rr_str = map[uint16]string{
	TypeCNAME:      "CNAME",
	TypeHINFO:      "HINFO",
	TypeTLSA:       "TSLA",
	TypeMB:         "MB",
	TypeMG:         "MG",
	TypeRP:         "RP",
	TypeMD:         "MD",
	TypeMF:         "MF",
	TypeMINFO:      "MINFO",
	TypeMR:         "MR",
	TypeMX:         "MX",
	TypeWKS:        "WKS",
	TypeNS:         "NS",
	TypePTR:        "PTR",
	TypeRT:         "RT",
	TypeSOA:        "SOA",
	TypeTXT:        "TXT",
	TypeSRV:        "SRV",
	TypeNAPTR:      "NAPTR",
	TypeKX:         "KX",
	TypeCERT:       "CERT",
	TypeDNAME:      "DNAME",
	TypeA:          "A",
	TypeAAAA:       "AAAA",
	TypeLOC:        "LOC",
	TypeOPT:        "OPT",
	TypeDS:         "DS",
	TypeDHCID:      "DHCID",
	TypeHIP:        "HIP",
	TypeIPSECKEY:   "IPSECKEY",
	TypeSSHFP:      "SSHFP",
	TypeRRSIG:      "RRSIG",
	TypeNSEC:       "NSEC",
	TypeDNSKEY:     "DNSKEY",
	TypeNSEC3:      "NSEC3",
	TypeNSEC3PARAM: "NSEC3PARAM",
	TypeTALINK:     "TALINK",
	TypeSPF:        "SPF",
	TypeTKEY:       "TKEY", // Meta RR
	TypeTSIG:       "TSIG", // Meta RR
	TypeAXFR:       "AXFR", // Meta RR
	TypeIXFR:       "IXFR", // Meta RR
	TypeANY:        "ANY",  // Meta RR
	TypeURI:        "URI",
	TypeTA:         "TA",
	TypeDLV:        "DLV",
}

// Reverse, needed for string parsing.
var Str_rr = reverseInt16(Rr_str)
var Str_class = reverseInt16(Class_str)

// Map of opcodes strings.
var Str_opcode = reverseInt(Opcode_str)

// Map of rcodes strings.
var Str_rcode = reverseInt(Rcode_str)

// Map of strings for each CLASS wire type.
var Class_str = map[uint16]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

// Map of strings for opcodes.
var Opcode_str = map[int]string{
	OpcodeQuery:  "QUERY",
	OpcodeIQuery: "IQUERY",
	OpcodeStatus: "STATUS",
	OpcodeNotify: "NOTIFY",
	OpcodeUpdate: "UPDATE",
}

// Map of strings for rcodes.
var Rcode_str = map[int]string{
	RcodeSuccess:        "NOERROR",
	RcodeFormatError:    "FORMERR",
	RcodeServerFailure:  "SERVFAIL",
	RcodeNameError:      "NXDOMAIN",
	RcodeNotImplemented: "NOTIMPL",
	RcodeRefused:        "REFUSED",
	RcodeYXDomain:       "YXDOMAIN", // From RFC 2136
	RcodeYXRrset:        "YXRRSET",
	RcodeNXRrset:        "NXRRSET",
	RcodeNotAuth:        "NOTAUTH",
	RcodeNotZone:        "NOTZONE",
	RcodeBadSig:         "BADSIG",
	RcodeBadKey:         "BADKEY",
	RcodeBadTime:        "BADTIME",
	RcodeBadMode:        "BADMODE",
	RcodeBadName:        "BADNAME",
	RcodeBadAlg:         "BADALG",
	RcodeBadTrunc:       "BADTRUNC",
}

// Rather than write the usual handful of routines to pack and
// unpack every message that can appear on the wire, we use
// reflection to write a generic pack/unpack for structs and then
// use it. Thus, if in the future we need to define new message
// structs, no new pack/unpack/printing code needs to be written.

// Domain names are a sequence of counted strings
// split at the dots. They end with a zero-length string.

// PackDomainName packs a domain name s into msg[off:].
// If compression is wanted compress must be true and the compression
// map needs to hold a mapping between domain names and offsets
// pointing into msg[].
func PackDomainName(s string, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	// Add trailing dot to canonicalize name.
	lenmsg := len(msg)
	ls := len(s)
	if ls == 0 || s[ls-1] != '.' {
		return lenmsg, ErrFqdn
	}

	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots.
	// There is also a trailing zero.

	// Compression
	nameoffset := -1
	pointer := -1

	// Emit sequence of counted strings, chopping at dots.
	begin := 0
	bs := []byte(s)
	//	ls := len(bs)
	lens := ls
	for i := 0; i < ls; i++ {
		if bs[i] == '\\' {
			for j := i; j < lens-1; j++ {
				bs[j] = bs[j+1]
			}
			ls--
			continue
		}

		if bs[i] == '.' {
			if i-begin >= 1<<6 { // top two bits of length must be clear
				return lenmsg, ErrShortBuf
			}
			// off can already (we're in a loop) be bigger than len(msg)
			// this happens when a name isn't fully qualified
			if off+1 > lenmsg {
				return lenmsg, ErrShortBuf
			}
			msg[off] = byte(i - begin)
			offset := off
			off++
			for j := begin; j < i; j++ {
				if off+1 > lenmsg {
					return lenmsg, ErrShortBuf
				}
				msg[off] = bs[j]
				off++
			}
			// Dont try to compress '.'
			if compression != nil && string(bs[begin:]) != ".'" {
				if p, ok := compression[string(bs[begin:])]; !ok {
					// Only offsets smaller than this can be used.
					if offset < maxCompressionOffset {
						compression[string(bs[begin:])] = offset
					}
				} else {
					// The first hit is the longest matching dname
					// keep the pointer offset we get back and store
					// the offset of the current name, because that's
					// where we need to insert the pointer later

					// If compress is true, we're  allowed to compress this dname
					if pointer == -1 && compress {
						pointer = p         // Where to point to
						nameoffset = offset // Where to point from
						break
					}
				}
			}
			begin = i + 1
		}
	}
	// Root label is special
	if string(bs) == "." {
		return off, nil
	}
	// If we did compression and we find something at the pointer here
	if pointer != -1 {
		// We have two bytes (14 bits) to put the pointer in
		msg[nameoffset], msg[nameoffset+1] = packUint16(uint16(pointer ^ 0xC000))
		off = nameoffset + 1
		goto End
	}
	msg[off] = 0
End:
	off++
	return off, nil
}

// Unpack a domain name.
// In addition to the simple sequences of counted strings above,
// domain names are allowed to refer to strings elsewhere in the
// packet, to avoid repeating common suffixes when returning
// many entries in a single domain.  The pointers are marked
// by a length byte with the top two bits set.  Ignoring those
// two bits, that byte and the next give a 14 bit offset from msg[0]
// where we should pick up the trail.
// Note that if we jump elsewhere in the packet,
// we return off1 == the offset after the first pointer we found,
// which is where the next record will start.
// In theory, the pointers are only allowed to jump backward.
// We let them jump anywhere and stop jumping after a while.

// UnpackDomainName unpacks a domain name into a string.
func UnpackDomainName(msg []byte, off int) (s string, off1 int, err error) {
	s = ""
	lenmsg := len(msg)
	ptr := 0 // number of pointers followed
Loop:
	for {
		if off >= lenmsg {
			return "", lenmsg, ErrShortBuf
		}
		c := int(msg[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// end of name
				if s == "" {
					return ".", off, nil
				}
				break Loop
			}
			// literal string
			if off+c > lenmsg {
				return "", lenmsg, ErrShortBuf
			}
			for j := off; j < off+c; j++ {
				if msg[j] == '.' {
					// literal dot, escape it
					s += "\\."
				} else {
					s += string(msg[j])
				}
			}
			s += "."
			off += c
		case 0xC0:
			// pointer to somewhere else in msg.
			// remember location after first ptr,
			// since that's how many bytes we consumed.
			// also, don't follow too many pointers --
			// maybe there's a loop.
			if off >= lenmsg {
				return "", lenmsg, ErrShortBuf
			}
			c1 := msg[off]
			off++
			if ptr == 0 {
				off1 = off
			}
			if ptr++; ptr > 10 {
				return "", lenmsg, ErrLoop
			}
			off = (c^0xC0)<<8 | int(c1)
		default:
			// 0x80 and 0x40 are reserved
			return "", lenmsg, ErrBit
		}
	}
	if ptr == 0 {
		off1 = off
	}
	return s, off1, nil
}

// PackStruct packs a dnsStruct to a msg. 
func PackStruct(any dnsStruct, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	err = any.Walk(func(field interface{}, name, tag string) error {
		lenmsg := len(msg)
		switch fv := field.(type) {
		default:
			return ErrTag
		case []string:
			switch tag {
			case "domain":
				for j := 0; j < len(fv); j++ {
					off, err = PackDomainName(fv[j], msg, off, compression, false && compress)
					if err != nil {
						return err
					}
				}
			case "txt":
				for j := 0; j < len(fv); j++ {
					element := fv[j]
					le := len(element)
					// Counted string: 1 byte length.
					if le > 255 || off+1+le > lenmsg {
						return ErrShortBuf
					}
					msg[off] = byte(le)
					off++
					for i := 0; i < le; i++ {
						msg[off+i] = element[i]
					}
					off += len(element)
				}
			}
		case []EDNS0:
			for j := 0; j < len(fv); j++ {
				element := fv[j]
				b, e := element.(EDNS0).pack()
				if e != nil {
					return e
				}
				// Option code
				msg[off], msg[off+1] = packUint16(element.(EDNS0).Option())
				// Length
				msg[off+2], msg[off+3] = packUint16(uint16(len(b)))
				off += 4
				// Actual data
				copy(msg[off:off+len(b)], b)
				off += len(b)
			}
		case *net.IP:
			switch tag {
			case "a":
				// It must be a slice of 4, even if it is 16, we encode
				// only the first 4
				switch len(*fv) {
				case net.IPv6len:
					if off+net.IPv4len > lenmsg {
						return ErrShortBuf
					}
					msg[off] = byte((*fv)[12])
					msg[off+1] = byte((*fv)[13])
					msg[off+2] = byte((*fv)[14])
					msg[off+3] = byte((*fv)[15])
					off += net.IPv4len
				case net.IPv4len:
					if off+net.IPv4len > lenmsg {
						return ErrShortBuf
					}
					msg[off] = byte((*fv)[0])
					msg[off+1] = byte((*fv)[1])
					msg[off+2] = byte((*fv)[2])
					msg[off+3] = byte((*fv)[3])
					off += net.IPv4len
				case 0:
					// Allowed, for dynamic updates
				default:
					return ErrShortBuf
				}
			case "aaaa":
				if len(*fv) > net.IPv6len || off+len(*fv) > lenmsg {
					return ErrShortBuf
				}

				for j := 0; j < net.IPv6len; j++ {
					msg[off] = byte((*fv)[j])
					off++
				}
			}
		case []uint16:
			switch tag {
			case "wks":
				if len(fv) == 0 {
					break
				}
				var bitmapbyte uint16
				for j := 0; j < len(fv); j++ {
					serv := uint16(fv[j])
					bitmapbyte = uint16(serv / 8)
					if int(bitmapbyte) > lenmsg {
						return ErrShortBuf
					}
					bit := uint16(serv) - bitmapbyte*8
					msg[bitmapbyte] = byte(1 << (7 - bit))
				}
				off += int(bitmapbyte)
			case "nsec": // NSEC/NSEC3
				// This is the uint16 type bitmap
				if len(fv) == 0 {
					// Do absolutely nothing
					break
				}

				lastwindow := uint16(0)
				length := uint16(0)
				if off+2 > lenmsg {
					return ErrShortBuf
				}
				for j := 0; j < len(fv); j++ {
					t := uint16(fv[j])
					window := uint16(t / 256)
					if lastwindow != window {
						// New window, jump to the new offset
						off += int(length) + 3
						if off > lenmsg {
							return ErrShortBuf
						}
					}
					length = (t - window*256) / 8
					bit := t - (window * 256) - (length * 8)
					if off+2+int(length) > lenmsg {
						return ErrShortBuf
					}

					// Setting the window #
					msg[off] = byte(window)
					// Setting the octets length
					msg[off+1] = byte(length + 1)
					// Setting the bit value for the type in the right octet
					msg[off+2+int(length)] |= byte(1 << (7 - bit))
					lastwindow = window
				}
				off += 2 + int(length)
				off++
				if off > lenmsg {
					return ErrShortBuf
				}
			}
		case *uint8:
			if off+1 > lenmsg {
				return ErrShortBuf
			}
			msg[off] = byte(*fv)
			off++
		case *uint16:
			if off+2 > lenmsg {
				return ErrShortBuf
			}
			msg[off] = byte(*fv >> 8)
			msg[off+1] = byte(*fv)
			off += 2
		case *uint32:
			if off+4 > lenmsg {
				return ErrShortBuf
			}
			msg[off] = byte(*fv >> 24)
			msg[off+1] = byte(*fv >> 16)
			msg[off+2] = byte(*fv >> 8)
			msg[off+3] = byte(*fv)
			off += 4
		case *uint64:
			// Only used in TSIG, where it stops at 48 bits, so we discard the upper 16
			if off+6 > lenmsg {
				return ErrShortBuf
			}
			msg[off] = byte(*fv >> 40)
			msg[off+1] = byte(*fv >> 32)
			msg[off+2] = byte(*fv >> 24)
			msg[off+3] = byte(*fv >> 16)
			msg[off+4] = byte(*fv >> 8)
			msg[off+5] = byte(*fv)
			off += 6
		case *string:
			// There are multiple string encodings.
			// The tag distinguishes ordinary strings from domain names.
			s := *fv
			switch tag {
			default:
				return ErrTag
			case "base64":
				b64, err := packBase64([]byte(s))
				if err != nil {
					return err
				}
				copy(msg[off:off+len(b64)], b64)
				off += len(b64)
			case "domain":
				if off, err = PackDomainName(s, msg, off, compression, false && compress); err != nil {
					return err
				}
			case "cdomain":
				if off, err = PackDomainName(s, msg, off, compression, true && compress); err != nil {
					return err
				}
			case "base32":
				b32, err := packBase32([]byte(s))
				if err != nil {
					return err
				}
				copy(msg[off:off+len(b32)], b32)
				off += len(b32)
			case "size-hex":
				fallthrough // when unpacking this is important, when packing we can just fallthrough
			case "hex":
				// There is no length encoded here
				h, err := hex.DecodeString(s)
				if err != nil {
					return err
				}
				if off+hex.DecodedLen(len(s)) > lenmsg {
					// Overflow
					return ErrShortBuf
				}
				copy(msg[off:off+hex.DecodedLen(len(s))], h)
				off += hex.DecodedLen(len(s))
			case "txt":
				fallthrough
			case "":
				// Counted string: 1 byte length.
				if len(s) > 255 || off+1+len(s) > lenmsg {
					return ErrShortBuf
				}
				msg[off] = byte(len(s))
				off++
				for i := 0; i < len(s); i++ {
					msg[off+i] = s[i]
				}
				off += len(s)
			}
		}
		return nil
	})
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

// UnpackStrct unpacks a dnsStruct from msg.
// Same restrictions as packStructValue.
func UnpackStruct(any dnsStruct, msg []byte, off int) (off1 int, err error) {
	lenmsg := len(msg)
	err = any.Walk(func(field interface{}, name, tag string) error {
		var rdstart int
		switch fv := field.(type) {
		default:
			return ErrTag
		case []string:
			switch tag {
			case "domain":
				// HIP record, a slice of names (or none)
				servers := make([]string, 0)
				var s string
				for off < lenmsg {
					s, off, err = UnpackDomainName(msg, off)
					if err != nil {
						return err
					}
					servers = append(servers, s)
				}
				fv = servers
			case "txt":
				txt := make([]string, 0)
				rdlength := rdlengthHelper(any)
			Txts:
				l := int(msg[off])
				if off+l+1 > lenmsg {
					return ErrShortBuf
				}
				txt = append(txt, string(msg[off+1:off+l+1]))
				off += l + 1
				if off < rdlength {
					// More
					goto Txts
				}
				fv = txt
			}
		case []EDNS0:
			rdlength := rdlengthHelper(any)
			if rdlength == 0 {
				// This is an EDNS0 (OPT Record) with no rdata. We can savely return here.
				break
			}
			edns := make([]EDNS0, 0)
			// Goto to this place, when there is a goto
			code := uint16(0)

			code, off = unpackUint16(msg, off) // Overflow? TODO
			optlen, off1 := unpackUint16(msg, off)
			if off1+int(optlen) > off+rdlength {
				return ErrShortBuf
			}
			switch code {
			case EDNS0NSID:
				e := new(EDNS0_NSID)
				e.unpack(msg[off1 : off1+int(optlen)])
				edns = append(edns, e)
				off = off1 + int(optlen)
			case EDNS0SUBNET:
				e := new(EDNS0_SUBNET)
				e.unpack(msg[off1 : off1+int(optlen)])
				edns = append(edns, e)
				off = off1 + int(optlen)
			}
			fv = edns
		case *net.IP:
			switch tag {
			case "a":
				if off+net.IPv4len > len(msg) {
					return ErrShortBuf
				}
				*fv = net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3])
				off += net.IPv4len
			case "aaaa":
				if off+net.IPv6len > lenmsg {
					return ErrShortBuf
				}
				*fv = net.IP{msg[off], msg[off+1], msg[off+2], msg[off+3], msg[off+4],
					msg[off+5], msg[off+6], msg[off+7], msg[off+8], msg[off+9], msg[off+10],
					msg[off+11], msg[off+12], msg[off+13], msg[off+14], msg[off+15]}
				off += net.IPv6len
			}
		case []uint16:
			switch tag {
			case "wks":
				// Rest of the record is the bitmap
				rdlength := rdlengthHelper(any)
				endrr := rdstart + rdlength
				serv := make([]uint16, 0)
				j := 0
				for off < endrr {
					b := msg[off]
					// Check the bits one by one, and set the type
					if b&0x80 == 0x80 {
						serv = append(serv, uint16(j*8+0))
					}
					if b&0x40 == 0x40 {
						serv = append(serv, uint16(j*8+1))
					}
					if b&0x20 == 0x20 {
						serv = append(serv, uint16(j*8+2))
					}
					if b&0x10 == 0x10 {
						serv = append(serv, uint16(j*8+3))
					}
					if b&0x8 == 0x8 {
						serv = append(serv, uint16(j*8+4))
					}
					if b&0x4 == 0x4 {
						serv = append(serv, uint16(j*8+5))
					}
					if b&0x2 == 0x2 {
						serv = append(serv, uint16(j*8+6))
					}
					if b&0x1 == 0x1 {
						serv = append(serv, uint16(j*8+7))
					}
					j++
					off++
				}
				fv = serv
			case "nsec": // NSEC/NSEC3
				// Rest of the record is the type bitmap
				rdlength := rdlengthHelper(any)
				if rdlength == 0 {
					return ErrFmt
				}
				endrr := rdstart + rdlength
				if off+2 > lenmsg {
					return ErrShortBuf
				}
				nsec := make([]uint16, 0)
				length := 0
				window := 0
				for off+2 < endrr {
					window = int(msg[off])
					length = int(msg[off+1])
					//println("off, windows, length, end", off, window, length, endrr)
					if length == 0 {
						// A length window of zero is strange. If there
						// the window should not have been specified. Bail out
						return ErrFmt
					}
					if length > 32 {
						return ErrFmt
					}

					// Walk the bytes in the window - and check the bit
					// setting..
					off += 2
					for j := 0; j < length; j++ {
						b := msg[off+j]
						// Check the bits one by one, and set the type
						if b&0x80 == 0x80 {
							nsec = append(nsec, uint16(window*256+j*8+0))
						}
						if b&0x40 == 0x40 {
							nsec = append(nsec, uint16(window*256+j*8+1))
						}
						if b&0x20 == 0x20 {
							nsec = append(nsec, uint16(window*256+j*8+2))
						}
						if b&0x10 == 0x10 {
							nsec = append(nsec, uint16(window*256+j*8+3))
						}
						if b&0x8 == 0x8 {
							nsec = append(nsec, uint16(window*256+j*8+4))
						}
						if b&0x4 == 0x4 {
							nsec = append(nsec, uint16(window*256+j*8+5))
						}
						if b&0x2 == 0x2 {
							nsec = append(nsec, uint16(window*256+j*8+6))
						}
						if b&0x1 == 0x1 {
							nsec = append(nsec, uint16(window*256+j*8+7))
						}
					}
					off += length
				}
				fv = nsec
			}
		case *uint8:
			if off+1 > lenmsg {
				return ErrShortBuf
			}
			*fv = uint8(msg[off])
			off++
		case *uint16:
			var i uint16
			if off+2 > lenmsg {
				return ErrShortBuf
			}
			i, off = unpackUint16(msg, off)
			*fv = i
		case *uint32:
			if off+4 > lenmsg {
				return ErrShortBuf
			}
			*fv = uint32(msg[off])<<24 | uint32(msg[off+1])<<16 |
				uint32(msg[off+2])<<8 | uint32(msg[off+3])
			off += 4
		case *uint64:
			// This is *only* used in TSIG where the last 48 bits are occupied
			// So for now, assume a uint48 (6 bytes)
			if off+6 > lenmsg {
				return ErrShortBuf
			}
			*fv = uint64(msg[off])<<40 | uint64(msg[off+1])<<32 | uint64(msg[off+2])<<24 | uint64(msg[off+3])<<16 |
				uint64(msg[off+4])<<8 | uint64(msg[off+5])
			off += 6
		case *string:
			var s string
			switch tag {
			default:
				return ErrTag
			case "hex":
				// Rest of the RR is hex encoded, network order an issue here?
				rdlength := rdlengthHelper(any)
				endrr := rdstart + rdlength
				if endrr > lenmsg {
					return ErrShortBuf
				}
				s = hex.EncodeToString(msg[off:endrr])
				off = endrr
			case "base64":
				// Rest of the RR is base64 encoded value
				rdlength := rdlengthHelper(any)
				endrr := rdstart + rdlength
				if endrr > lenmsg {
					return ErrShortBuf
				}
				s = unpackBase64(msg[off:endrr])
				off = endrr
			case "cdomain":
				fallthrough
			case "domain":
				s, off, err = UnpackDomainName(msg, off)
				if err != nil {
					return err
				}
			case "base32":
				/*
					// XXX(mg): This is of course ugly as hell
					var size int
					switch reflect.ValueOf(fv).Elem().Type().Name() {
					case "RR_NSEC3":
						switch reflect.ValueOf(fv).Elem().Type().Field(i).Name {
						case "NextDomain":
							name := val.FieldByName("HashLength")
							size = int(name.Uint())
						}
					}
					if off+size > lenmsg {
						println("dns: failure unpacking base32 string")
						return false
					}
					s = unpackBase32(msg[off : off+size])
					off += size
				*/
			case "size-hex":
				// a "size" string, but it must be encoded in hex in the string
				var size int
				switch t := any.(type) {
				case *RR_NSEC3:
					switch name {
					case "Salt":
						size = int(t.SaltLength)
					case "NextDomain":
						size = int(t.HashLength)
					}
				case *RR_TSIG:
					switch name {
					case "MAC":
						size = int(t.MACSize)
					case "OtherData":
						size = int(t.OtherLen)
					}
				}
				if off+size > lenmsg {
					return ErrShortBuf
				}
				s = hex.EncodeToString(msg[off : off+size])
				off += size
			case "txt":
				// 1 txt piece
				rdlength := int(any.Header().Rdlength)
			Txt:
				if off >= lenmsg || off+1+int(msg[off]) > lenmsg {
					return ErrShortBuf
				}
				n := int(msg[off])
				off++
				for i := 0; i < n; i++ {
					s += string(msg[off+i])
				}
				off += n
				if off < rdlength {
					// More to
					goto Txt
				}
			case "":
				if off >= lenmsg || off+1+int(msg[off]) > lenmsg {
					return ErrShortBuf
				}
				n := int(msg[off])
				off++
				for i := 0; i < n; i++ {
					s += string(msg[off+i])
				}
				off += n
			}
			*fv = s
		}
		return nil
	})
	if err != nil {
		return lenmsg, err
	}
	return off, nil
}

// Helper function for unpacking
func unpackUint16(msg []byte, off int) (v uint16, off1 int) {
	v = uint16(msg[off])<<8 | uint16(msg[off+1])
	off1 = off + 2
	return
}

func unpackBase32(b []byte) string {
	b32 := make([]byte, base32.HexEncoding.EncodedLen(len(b)))
	base32.HexEncoding.Encode(b32, b)
	return string(b32)
}

func unpackBase64(b []byte) string {
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(b64, b)
	return string(b64)
}

// Helper function for packing
func packUint16(i uint16) (byte, byte) {
	return byte(i >> 8), byte(i)
}

func packBase64(s []byte) ([]byte, error) {
	b64len := base64.StdEncoding.DecodedLen(len(s))
	buf := make([]byte, b64len)
	n, err := base64.StdEncoding.Decode(buf, []byte(s))
	if err != nil {
		return nil, err
	}
	buf = buf[:n]
	return buf, nil
}

// Helper function for packing, mostly used in dnssec.go
func packBase32(s []byte) ([]byte, error) {
	b32len := base32.HexEncoding.DecodedLen(len(s))
	buf := make([]byte, b32len)
	n, err := base32.HexEncoding.Decode(buf, []byte(s))
	if err != nil {
		return nil, err
	}
	buf = buf[:n]
	return buf, nil
}

// Resource record packer.
func PackRR(rr RR, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	if rr == nil {
		return len(msg), ErrFmt
	}

	off1, err = PackStruct(rr, msg, off, compression, compress)
	if err != nil {
		return len(msg), err
	}
	if !rawSetRdlength(msg, off, off1) {
		return len(msg), ErrShortBuf
	}
	return off1, nil
}

// Resource record unpacker.
func UnpackRR(msg []byte, off int) (rr RR, off1 int, err error) {
	// unpack just the header, to find the rr type and length
	var h RR_Header
	off0 := off
	if off, err = UnpackStruct(&h, msg, off); err != nil {
		return nil, len(msg), err
	}
	end := off + int(h.Rdlength)
	// make an rr of that type and re-unpack.
	mk, known := rr_mk[h.Rrtype]
	if !known {
		rr = new(RR_RFC3597)
	} else {
		rr = mk()
	}
	off, err = UnpackStruct(rr, msg, off0)
	if off != end {
		return &h, end, nil
	}
	return rr, off, err
}

// Reverse a map
func reverseInt8(m map[uint8]string) map[string]uint8 {
	n := make(map[string]uint8)
	for u, s := range m {
		n[s] = u
	}
	return n
}

func reverseInt16(m map[uint16]string) map[string]uint16 {
	n := make(map[string]uint16)
	for u, s := range m {
		n[s] = u
	}
	return n
}

func reverseInt(m map[int]string) map[string]int {
	n := make(map[string]int)
	for u, s := range m {
		n[s] = u
	}
	return n
}

// Convert a MsgHdr to a string, with dig-like headers:
//
//;; opcode: QUERY, status: NOERROR, id: 48404
//
//;; flags: qr aa rd ra;
func (h *MsgHdr) String() string {
	if h == nil {
		return "<nil> MsgHdr"
	}

	s := ";; opcode: " + Opcode_str[h.Opcode]
	s += ", status: " + Rcode_str[h.Rcode]
	s += ", id: " + strconv.Itoa(int(h.Id)) + "\n"

	s += ";; flags:"
	if h.Response {
		s += " qr"
	}
	if h.Authoritative {
		s += " aa"
	}
	if h.Truncated {
		s += " tc"
	}
	if h.RecursionDesired {
		s += " rd"
	}
	if h.RecursionAvailable {
		s += " ra"
	}
	if h.Zero { // Hmm
		s += " z"
	}
	if h.AuthenticatedData {
		s += " ad"
	}
	if h.CheckingDisabled {
		s += " cd"
	}

	s += ";"
	return s
}

// Pack packs a Msg: it is converted to to wire format.
// If the dns.Compress is true the message will be in compressed wire format.
func (dns *Msg) Pack() (msg []byte, err error) {
	if dns == nil {
		return nil, ErrFmt
	}
	var dh Header
	compression := make(map[string]int) // Compression pointer mappings

	// Convert convenient Msg into wire-like Header.
	dh.Id = dns.Id
	dh.Bits = uint16(dns.Opcode)<<11 | uint16(dns.Rcode)
	if dns.Response {
		dh.Bits |= _QR
	}
	if dns.Authoritative {
		dh.Bits |= _AA
	}
	if dns.Truncated {
		dh.Bits |= _TC
	}
	if dns.RecursionDesired {
		dh.Bits |= _RD
	}
	if dns.RecursionAvailable {
		dh.Bits |= _RA
	}
	if dns.Zero {
		dh.Bits |= _Z
	}
	if dns.AuthenticatedData {
		dh.Bits |= _AD
	}
	if dns.CheckingDisabled {
		dh.Bits |= _CD
	}

	// Prepare variable sized arrays.
	question := dns.Question
	answer := dns.Answer
	ns := dns.Ns
	extra := dns.Extra

	dh.Qdcount = uint16(len(question))
	dh.Ancount = uint16(len(answer))
	dh.Nscount = uint16(len(ns))
	dh.Arcount = uint16(len(extra))

	// TODO(mg): still a little too much, but better than 64K...
	msg = make([]byte, dns.Len()+10)

	// Pack it in: header and then the pieces.
	off := 0
	off, err = PackStruct(&dh, msg, off, compression, dns.Compress)
	for i := 0; i < len(question); i++ {
		off, err = PackStruct(&question[i], msg, off, compression, dns.Compress)
	}
	for i := 0; i < len(answer); i++ {
		off, err = PackRR(answer[i], msg, off, compression, dns.Compress)
	}
	for i := 0; i < len(ns); i++ {
		off, err = PackRR(ns[i], msg, off, compression, dns.Compress)
	}
	for i := 0; i < len(extra); i++ {
		off, err = PackRR(extra[i], msg, off, compression, dns.Compress)
	}
	if err != nil {
		return nil, err
	}
	//println("allocated", dns.Len()+1, "used", off)
	return msg[:off], nil
}

// Unpack unpacks a binary message to a Msg structure.
func (dns *Msg) Unpack(msg []byte) (err error) {
	// Header.
	var dh Header
	off := 0
	if off, err = UnpackStruct(&dh, msg, off); err != nil {
		return err
	}
	dns.Id = dh.Id
	dns.Response = (dh.Bits & _QR) != 0
	dns.Opcode = int(dh.Bits>>11) & 0xF
	dns.Authoritative = (dh.Bits & _AA) != 0
	dns.Truncated = (dh.Bits & _TC) != 0
	dns.RecursionDesired = (dh.Bits & _RD) != 0
	dns.RecursionAvailable = (dh.Bits & _RA) != 0
	dns.Zero = (dh.Bits & _Z) != 0
	dns.AuthenticatedData = (dh.Bits & _AD) != 0
	dns.CheckingDisabled = (dh.Bits & _CD) != 0
	dns.Rcode = int(dh.Bits & 0xF)

	// Arrays.
	dns.Question = make([]Question, dh.Qdcount)
	dns.Answer = make([]RR, dh.Ancount)
	dns.Ns = make([]RR, dh.Nscount)
	dns.Extra = make([]RR, dh.Arcount)

	for i := 0; i < len(dns.Question); i++ {
		off, err = UnpackStruct(&dns.Question[i], msg, off)
	}
	for i := 0; i < len(dns.Answer); i++ {
		dns.Answer[i], off, err = UnpackRR(msg, off)
	}
	for i := 0; i < len(dns.Ns); i++ {
		dns.Ns[i], off, err = UnpackRR(msg, off)
	}
	for i := 0; i < len(dns.Extra); i++ {
		dns.Extra[i], off, err = UnpackRR(msg, off)
	}
	if err != nil {
		return err
	}
	if off != len(msg) {
		return ErrShortBuf
	}
	return nil
}

// Convert a complete message to a string with dig-like output.
func (dns *Msg) String() string {
	if dns == nil {
		return "<nil> MsgHdr"
	}
	s := dns.MsgHdr.String() + " "
	s += "QUERY: " + strconv.Itoa(len(dns.Question)) + ", "
	s += "ANSWER: " + strconv.Itoa(len(dns.Answer)) + ", "
	s += "AUTHORITY: " + strconv.Itoa(len(dns.Ns)) + ", "
	s += "ADDITIONAL: " + strconv.Itoa(len(dns.Extra)) + "\n"
	if len(dns.Question) > 0 {
		s += "\n;; QUESTION SECTION:\n"
		for i := 0; i < len(dns.Question); i++ {
			s += dns.Question[i].String() + "\n"
		}
	}
	if len(dns.Answer) > 0 {
		s += "\n;; ANSWER SECTION:\n"
		for i := 0; i < len(dns.Answer); i++ {
			if dns.Answer[i] != nil {
				s += dns.Answer[i].String() + "\n"
			}
		}
	}
	if len(dns.Ns) > 0 {
		s += "\n;; AUTHORITY SECTION:\n"
		for i := 0; i < len(dns.Ns); i++ {
			if dns.Ns[i] != nil {
				s += dns.Ns[i].String() + "\n"
			}
		}
	}
	if len(dns.Extra) > 0 {
		s += "\n;; ADDITIONAL SECTION:\n"
		for i := 0; i < len(dns.Extra); i++ {
			if dns.Extra[i] != nil {
				s += dns.Extra[i].String() + "\n"
			}
		}
	}
	return s
}

// Len return the message length when in (un)compressed wire format.
// If dns.Compress is true compression is taken into account, currently
// this only counts owner name compression. There is no check for 
// nil valued sections (allocated, but contains no RRs).
func (dns *Msg) Len() int {
	// Message header is always 12 bytes       
	l := 12
	var compression map[string]int
	if dns.Compress {
		compression = make(map[string]int)
	}

	for i := 0; i < len(dns.Question); i++ {
		l += dns.Question[i].Len()
		if dns.Compress {
			compressionHelper(compression, dns.Question[i].Name)
		}
	}
	for i := 0; i < len(dns.Answer); i++ {
		if dns.Compress {
			if v, ok := compression[dns.Answer[i].Header().Name]; ok {
				l += dns.Answer[i].Len() - v
				continue
			}
			compressionHelper(compression, dns.Answer[i].Header().Name)
		}
		l += dns.Answer[i].Len()
	}
	for i := 0; i < len(dns.Ns); i++ {
		if dns.Compress {
			if v, ok := compression[dns.Ns[i].Header().Name]; ok {
				l += dns.Ns[i].Len() - v
				continue
			}
			compressionHelper(compression, dns.Ns[i].Header().Name)
		}
		l += dns.Ns[i].Len()
	}
	for i := 0; i < len(dns.Extra); i++ {
		if dns.Compress {
			if v, ok := compression[dns.Extra[i].Header().Name]; ok {
				l += dns.Extra[i].Len() - v
				continue
			}
			compressionHelper(compression, dns.Extra[i].Header().Name)
		}
		l += dns.Extra[i].Len()
	}
	return l
}

func compressionHelper(c map[string]int, s string) {
	pref := ""
	lbs := SplitLabels(s)
	for j := len(lbs) - 1; j >= 0; j-- {
		c[lbs[j]+"."+pref] = 1 + len(pref) + len(lbs[j])
		pref = lbs[j] + "." + pref
	}
}

func rdlengthHelper(any dnsStruct) int {
	if any.Header() == nil {
		return 0
	}
	return int(any.Header().Rdlength)
}

// Id return a 16 bits random number to be used as a
// message id. The random provided should be good enough.
func Id() uint16 {
	return uint16(rand.Int()) ^ uint16(time.Now().Nanosecond())
}
