package dnsmsg

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// A realistic response: example.com A 93.184.216.34, TTL 300, the answer name compressed with a pointer.
const examplePacket = "123481800001000100000000" +
	"076578616d706c6503636f6d0000010001" +
	"c00c000100010000012c00045db8d822"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wireName(s string) []byte {
	var b []byte
	for _, l := range strings.Split(s, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

type rr struct {
	name string
	typ  uint16
	ttl  uint32
	data []byte
}

func build(q string, qtype, flags uint16, rrs ...rr) []byte {
	b := []byte{0x12, 0x34, byte(flags >> 8), byte(flags), 0, 1, 0, byte(len(rrs)), 0, 0, 0, 0}
	b = append(b, wireName(q)...)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1)
	for _, r := range rrs {
		b = append(b, wireName(r.name)...)
		b = binary.BigEndian.AppendUint16(b, r.typ)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, r.ttl)
		b = binary.BigEndian.AppendUint16(b, uint16(len(r.data)))
		b = append(b, r.data...)
	}
	return b
}

func TestParseExample(t *testing.T) {
	m, err := Parse(unhex(t, examplePacket))
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0x1234 || !m.Response || m.Truncated || m.RCode != 0 || m.Question != "example.com" || m.QType != TypeA {
		t.Errorf("header: %+v", m)
	}
	want := []Answer{{Name: "example.com", Type: TypeA, TTL: 300, Addr: netip.MustParseAddr("93.184.216.34")}}
	if !reflect.DeepEqual(m.Answers, want) {
		t.Errorf("answers: %+v, expected %+v", m.Answers, want)
	}
	names, addrs, ttl := m.Resolve()
	if !reflect.DeepEqual(names, []string{"example.com"}) || len(addrs) != 1 || addrs[0] != want[0].Addr || ttl != 300 {
		t.Errorf("Resolve: %v %v %d", names, addrs, ttl)
	}
}

func TestResolveCNAMEChain(t *testing.T) {
	pkt := build("www.youtube.com", TypeA, 0x8180,
		rr{"www.youtube.com", TypeCNAME, 86400, wireName("youtube-ui.l.google.com")},
		rr{"youtube-ui.l.google.com", TypeCNAME, 900, wireName("wide-youtube.l.google.com")},
		rr{"wide-youtube.l.google.com", TypeA, 200, []byte{142, 251, 150, 4}},
		rr{"wide-youtube.l.google.com", TypeA, 120, []byte{142, 251, 151, 4}},
		rr{"other.example", TypeA, 5, []byte{1, 1, 1, 1}},
	)
	m, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	names, addrs, ttl := m.Resolve()
	wantNames := []string{"www.youtube.com", "youtube-ui.l.google.com", "wide-youtube.l.google.com"}
	wantAddrs := []netip.Addr{netip.MustParseAddr("142.251.150.4"), netip.MustParseAddr("142.251.151.4")}
	if !reflect.DeepEqual(names, wantNames) || !reflect.DeepEqual(addrs, wantAddrs) || ttl != 120 {
		t.Errorf("Resolve: %v %v %d", names, addrs, ttl)
	}
}

func TestResolveCNAMELoopTerminates(t *testing.T) {
	pkt := build("a.example", TypeA, 0x8180,
		rr{"a.example", TypeCNAME, 60, wireName("b.example")},
		rr{"b.example", TypeCNAME, 60, wireName("a.example")},
	)
	m, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	names, addrs, _ := m.Resolve()
	if !reflect.DeepEqual(names, []string{"a.example", "b.example"}) || len(addrs) != 0 {
		t.Errorf("Resolve: %v %v", names, addrs)
	}
}

func TestParseLowercasesNames(t *testing.T) {
	pkt := build("yOuTuBe.CoM", TypeA, 0x8180, rr{"YOUTUBE.com", TypeA, 60, []byte{1, 2, 3, 4}})
	m, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if m.Question != "youtube.com" || m.Answers[0].Name != "youtube.com" {
		t.Errorf("names were not lowercased: %q, %q", m.Question, m.Answers[0].Name)
	}
	if _, addrs, _ := m.Resolve(); len(addrs) != 1 {
		t.Errorf("address lost because of case: %v", addrs)
	}
}

func TestParseOtherRecords(t *testing.T) {
	v6 := netip.MustParseAddr("2a00:1450:4010:c0e::5b")
	pkt := build("example.com", TypeAAAA, 0x8180,
		rr{"example.com", TypeAAAA, 60, v6.AsSlice()},
		rr{"example.com", 16, 60, []byte{3, 'a', 'b', 'c'}}, // TXT
	)
	m, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answers) != 2 || m.Answers[0].Addr != v6 || m.Answers[1].Type != 16 {
		t.Errorf("answers: %+v", m.Answers)
	}
	if _, addrs, _ := m.Resolve(); len(addrs) != 0 {
		t.Errorf("Resolve returned non-IPv4 addresses: %v", addrs)
	}
}

func TestParseFlags(t *testing.T) {
	m, err := Parse(build("nope.example", TypeA, 0x8183)) // NXDOMAIN
	if err != nil {
		t.Fatal(err)
	}
	if m.RCode != 3 || len(m.Answers) != 0 {
		t.Errorf("NXDOMAIN: %+v", m)
	}
	m, err = Parse(build("big.example", TypeA, 0x8380)) // truncated response
	if err != nil {
		t.Fatal(err)
	}
	if !m.Truncated {
		t.Error("truncation flag was not read")
	}
	m, err = Parse(build("q.example", TypeA, 0x0100)) // a query, not a response
	if err != nil {
		t.Fatal(err)
	}
	if m.Response {
		t.Error("a query was taken for a response")
	}
}

func TestParseTruncated(t *testing.T) {
	pkt := unhex(t, examplePacket)
	for i := 0; i < len(pkt); i++ {
		if _, err := Parse(pkt[:i]); !errors.Is(err, ErrMalformed) {
			t.Errorf("truncated to %d bytes: error %v, expected ErrMalformed", i, err)
		}
	}
}

func TestParsePointerLoop(t *testing.T) {
	// The question is a pointer to itself.
	pkt := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1}
	if _, err := Parse(pkt); !errors.Is(err, ErrMalformed) {
		t.Errorf("pointer loop: error %v, expected ErrMalformed", err)
	}
}

func TestParseRejectsBadCounts(t *testing.T) {
	pkt := unhex(t, examplePacket)
	noQuestion := append([]byte{}, pkt...)
	noQuestion[5] = 0
	if _, err := Parse(noQuestion); !errors.Is(err, ErrMalformed) {
		t.Errorf("no question: error %v", err)
	}
	badA := build("example.com", TypeA, 0x8180, rr{"example.com", TypeA, 60, []byte{1, 2, 3}})
	if _, err := Parse(badA); !errors.Is(err, ErrMalformed) {
		t.Errorf("3-byte A record: error %v", err)
	}
}

// svcb builds SVCB/HTTPS record data: priority 1, target "." (the owner itself), then parameters.
func svcb(params ...[]byte) []byte {
	b := []byte{0, 1, 0}
	for _, p := range params {
		b = append(b, p...)
	}
	return b
}

func param(key uint16, value []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, key)
	b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
	return append(b, value...)
}

func TestResolveIPv4Hints(t *testing.T) {
	https := svcb(param(1, []byte{2, 'h', '2'}), param(4, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	m, err := Parse(build("video.example", TypeHTTPS, 0x8180, rr{"video.example", TypeHTTPS, 300, https}))
	if err != nil {
		t.Fatal(err)
	}
	names, addrs, ttl := m.Resolve()
	want := []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")}
	if !reflect.DeepEqual(names, []string{"video.example"}) || !reflect.DeepEqual(addrs, want) || ttl != 300 {
		t.Errorf("hints: %v %v %d", names, addrs, ttl)
	}

	// Through a CNAME: the hints of the target count.
	m, err = Parse(build("www.example", TypeHTTPS, 0x8180,
		rr{"www.example", TypeCNAME, 60, wireName("cdn.example")},
		rr{"cdn.example", TypeHTTPS, 120, svcb(param(4, []byte{9, 9, 9, 9}))}))
	if err != nil {
		t.Fatal(err)
	}
	names, addrs, ttl = m.Resolve()
	if !reflect.DeepEqual(names, []string{"www.example", "cdn.example"}) || !reflect.DeepEqual(addrs, []netip.Addr{netip.MustParseAddr("9.9.9.9")}) || ttl != 120 {
		t.Errorf("hints through a CNAME: %v %v %d", names, addrs, ttl)
	}

	// A malformed hint parameter does not spoil the rest of the answer.
	m, err = Parse(build("mixed.example", TypeA, 0x8180,
		rr{"mixed.example", TypeHTTPS, 300, svcb(param(4, []byte{1, 2, 3}))},
		rr{"mixed.example", TypeA, 60, []byte{7, 7, 7, 7}}))
	if err != nil {
		t.Fatalf("a malformed HTTPS record spoiled the answer: %v", err)
	}
	if _, addrs, ttl = m.Resolve(); !reflect.DeepEqual(addrs, []netip.Addr{netip.MustParseAddr("7.7.7.7")}) || ttl != 60 {
		t.Errorf("A record next to a malformed HTTPS record: %v %d", addrs, ttl)
	}
}
