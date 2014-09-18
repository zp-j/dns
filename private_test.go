package dns

import (
	"testing"
)

const TypeMAGIC uint16 = 0x0F01

type MAGIC struct {
	Hdr  RR_Header
	Code string `dns:"hex"`
}

func (rr *MAGIC) Header() *RR_Header { return &rr.Hdr }
func (rr *MAGIC) Copy() RR {
	return &MAGIC{RR_Header{hdr.Name, hdr.Rrtype, hdr.Class, hdr.Ttl, hdr.Rdlength}, rr.Code}
}
func (rr *MAGIC) Len() int       { return rr.Hdr.Len() + 64 }
func (rr *MAGIC) String() string { return rr.Hdr.String() + fmt.Sprintf("%x", []byte(rr.Code)) }

func ReadMagic(hdr RR_Header, l Lexem, _ string) (RR, error, string) {
	s := l.Token()
	buf := make([]byte, 100)
	num, err := hex.Decode(buf, []byte(s))
	if err != nil {
		return nil, err, ""
	}
	return &MAGIC{hdr, string(buf[:num])}, nil, ""
}

//var CustomLexemReaders = map[uint16]func(Lexem, string) (RR, error, string){}

func TestMAGIC(t *testing.T) {
	//	dns.TypeToRR[TypeMAGIC] = func() dns.RR { return new(MAGIC) }
	//	dns.TypeToString[TypeMAGIC] = "MAGIC"
	//	dns.StringToType["MAGIC"] = TypeMAGIC
	//	dns.CustomLexemReaders[TypeMAGIC] = ReadMagic
	//	defer func() {
	//		delete(dns.TypeToRR, TypeMAGIC)
	//		delete(dns.TypeToString, TypeMAGIC)
	//		delete(dns.StringToType, "MAGIC")
	//		delete(dns.CustomLexemReaders, TypeMAGIC)
	//	}()
	x := &MAGIC{RR_Header{Name: "example.org.", Rrtype: TypeMAGIC, Class: ClassINET, Ttl: 30}, "0123"}

	buf := make([]byte, 1024)
	off, err := dns.PackRR(x, buf, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	y, _, err := dns.UnpackRR(buf[:off], 0)
	if err != nil {
		t.Fatal(err)
	}
	/*
	if x.String() != y.String() {
		t.Errorf("Record text representation does not match after parsing wire fmt: %#v != %#v", x, y)
	}

	n, err := dns.NewRR(y.String())
	if err != nil {
		t.Fatal(err)
	}
	if x.String() != n.String() {
		t.Errorf("Record text representation does not match after parsing string: %#v != %#v", x, n)
	}
	*/
}
