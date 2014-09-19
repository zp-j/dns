package dns

import (
	"encoding/hex"
	"fmt"
	"testing"
)

const typeMAGIC uint16 = 0x0F01

type MAGIC struct {
	Hdr  RR_Header
	Code string `dns:"hex"`
}

func (rr *MAGIC) Header() *RR_Header { return &rr.Hdr }
func (rr *MAGIC) String() string     { return rr.Hdr.String() + fmt.Sprintf("%x", []byte(rr.Code)) }
func (rr *MAGIC) Len() int           { return rr.Hdr.Len() + 64 }
func (rr *MAGIC) Copy() RR {
	return &MAGIC{RR_Header{rr.Hdr.Name, rr.Hdr.Rrtype, rr.Hdr.Class, rr.Hdr.Ttl, rr.Hdr.Rdlength}, rr.Code}
}

func parseMagic(hdr RR_Header, l *Lexer, origin string) (RR, *ParseError, string) {
	l.Next()
	s := l.Token()
	buf := make([]byte, 100)
	num, err := hex.Decode(buf, []byte(s))
	if err != nil {
		return nil, l.NewParseError(err), ""
	}
	// TODO: Need to read to end of the line, otherwise stuff
	// will break.
	return &MAGIC{hdr, string(buf[:num])}, nil, l.Comment()
}

func TestMAGIC(t *testing.T) {
	TypeToRR[typeMAGIC] = func() RR { return new(MAGIC) }
	TypeToString[typeMAGIC] = "MAGIC"
	StringToType["MAGIC"] = typeMAGIC
	PrivateParserFunc[typeMAGIC] = parseMagic
	defer func() {
		delete(TypeToRR, typeMAGIC)
		delete(TypeToString, typeMAGIC)
		delete(StringToType, "MAGIC")
		delete(PrivateParserFunc, typeMAGIC)
	}()
	x := &MAGIC{RR_Header{Name: "example.org.", Rrtype: typeMAGIC, Class: ClassINET, Ttl: 30}, "0123"}

	buf := make([]byte, 1024)
	off, err := PackRR(x, buf, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	y, _, err := UnpackRR(buf[:off], 0)
	if err != nil {
		t.Fatal(err)
	}
	if x.String() != y.String() {
		t.Errorf("Record text representation does not match after parsing wire fmt: %#v != %#v", x, y)
	}

	n, err := NewRR(y.String())
	if err != nil {
		t.Fatal(err)
	}
	if x.String() != n.String() {
		t.Errorf("Record text representation does not match after parsing string: %#v != %#v", x, n)
	}
}
