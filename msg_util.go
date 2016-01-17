package dns

// Utility functions for packing and unpacking.

import (
	"encoding/base32"
	"encoding/base64"
	"math/big"
)

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func dddToByte(s []byte) byte {
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func intToBytes(i *big.Int, length int) []byte {
	buf := i.Bytes()
	if len(buf) < length {
		b := make([]byte, length)
		copy(b[length-len(buf):], buf)
		return b
	}
	return buf
}

func fromBase32(s []byte) (buf []byte, err error) {
	buflen := base32.HexEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base32.HexEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func toBase32(b []byte) string { return base32.HexEncoding.EncodeToString(b) }
func toBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unpackUint16(msg []byte, off int) (uint16, int) {
	return uint16(msg[off])<<8 | uint16(msg[off+1]), off + 2
}
func unpackUint32(msg []byte, off int) (uint32, int) {
	return uint32(uint64(uint32(msg[off])<<24 | uint32(msg[off+1])<<16 | uint32(msg[off+2])<<8 | uint32(msg[off+3]))), off + 4
}

func packUint16(i uint16) (byte, byte) { return byte(i >> 8), byte(i) }
func packUint32(i uint32) (byte, byte, byte, byte) {
	return byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)
}
