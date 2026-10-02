package nfq

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestConfigCmdMatchesKernelAcceptedBytes(t *testing.T) {
	// Привязка очереди 5353, номер запроса 1 — в точности то, что ядро роутера приняло при разведке.
	want := unhex(t, "1c000000"+"0203"+"0500"+"01000000"+"00000000"+"0000"+"14e9"+"0800"+"0100"+"01000002")
	if got := configCmd(5353, cfgCmdBind, 1); !bytes.Equal(got, want) {
		t.Errorf("привязка:\n%x\nожидалось:\n%x", got, want)
	}
}

func TestConfigParams(t *testing.T) {
	// Копировать пакет целиком (до 65535 байт): значение из 5 байт, атрибут выровнен до 12.
	want := unhex(t, "20000000"+"0203"+"0500"+"02000000"+"00000000"+"0000"+"14e9"+"0900"+"0200"+"0000ffff"+"02"+"000000")
	if got := configParams(5353, copyPacket, 0xffff, 2); !bytes.Equal(got, want) {
		t.Errorf("параметры:\n%x\nожидалось:\n%x", got, want)
	}
}

func TestConfigMaxLenAndFlags(t *testing.T) {
	want := unhex(t, "1c000000"+"0203"+"0500"+"03000000"+"00000000"+"0000"+"14e9"+"0800"+"0300"+"00000100")
	if got := configMaxLen(5353, 256, 3); !bytes.Equal(got, want) {
		t.Errorf("длина очереди:\n%x\nожидалось:\n%x", got, want)
	}
	want = unhex(t, "24000000"+"0203"+"0500"+"04000000"+"00000000"+"0000"+"14e9"+
		"0800"+"0500"+"00000001"+"0800"+"0400"+"00000001")
	if got := configFlags(5353, flagFailOpen, flagFailOpen, 4); !bytes.Equal(got, want) {
		t.Errorf("признаки:\n%x\nожидалось:\n%x", got, want)
	}
}

func TestVerdict(t *testing.T) {
	want := unhex(t, "20000000"+"0103"+"0100"+"00000000"+"00000000"+"0000"+"14e9"+"0c00"+"0200"+"00000001"+"00000007")
	if got := verdict(5353, 7, verdictAccept); !bytes.Equal(got, want) {
		t.Errorf("вердикт:\n%x\nожидалось:\n%x", got, want)
	}
}

func TestParseAck(t *testing.T) {
	ok := unhex(t, "24000000"+"0200"+"0000"+"05000000"+"00000000"+"00000000"+"00000000000000000000000000000000")
	rs, err := parse(ok)
	if err != nil || len(rs) != 1 || !rs[0].ack || rs[0].seq != 5 || rs[0].errno != 0 {
		t.Errorf("подтверждение: %+v, %v", rs, err)
	}
	denied := unhex(t, "24000000"+"0200"+"0000"+"06000000"+"00000000"+"ffffffff"+"00000000000000000000000000000000")
	rs, err = parse(denied)
	if err != nil || len(rs) != 1 || rs[0].errno != -1 || rs[0].seq != 6 {
		t.Errorf("отказ: %+v, %v", rs, err)
	}
}

// kernelPacket собирает сообщение ядра «пакет в очереди» теми же средствами, что и исходящие сообщения.
func kernelPacket(id uint32, payload []byte) []byte {
	hdr := []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id), 0x08, 0x00, 4}
	return message(msgPacket, 0, 0, 5353, attr(attrPacketHdr, hdr), attr(3, []byte{0, 0, 0, 0}), attr(attrPayload, payload))
}

func TestParsePackets(t *testing.T) {
	// Два пакета в одной порции данных; полезная нагрузка нечётной длины проверяет выравнивание.
	data := append(kernelPacket(42, []byte("hello")), kernelPacket(43, []byte("worlds!"))...)
	rs, err := parse(data)
	if err != nil || len(rs) != 2 {
		t.Fatalf("%+v, %v", rs, err)
	}
	if rs[0].packet == nil || rs[0].packet.ID != 42 || string(rs[0].packet.Payload) != "hello" {
		t.Errorf("первый пакет: %+v", rs[0].packet)
	}
	if rs[1].packet == nil || rs[1].packet.ID != 43 || string(rs[1].packet.Payload) != "worlds!" {
		t.Errorf("второй пакет: %+v", rs[1].packet)
	}
}

func TestParseIgnoresUnknownMessages(t *testing.T) {
	other := message(msgVerdict, 0, 0, 5353) // сообщение не того типа
	rs, err := parse(append(other, kernelPacket(1, []byte("x"))...))
	if err != nil || len(rs) != 1 || rs[0].packet == nil {
		t.Errorf("%+v, %v", rs, err)
	}
}

func TestParseMalformedNeverPanics(t *testing.T) {
	good := kernelPacket(42, []byte("hello"))
	for i := 1; i < len(good); i++ {
		if _, err := parse(good[:i]); !errors.Is(err, errMalformed) {
			t.Errorf("обрезка до %d байт: ошибка %v, ожидалась errMalformed", i, err)
		}
	}
	noID := message(msgPacket, 0, 0, 5353, attr(attrPayload, []byte("x")))
	if _, err := parse(noID); !errors.Is(err, errMalformed) {
		t.Errorf("пакет без номера: ошибка %v", err)
	}
	badAttr := append([]byte{}, good...)
	badAttr[20], badAttr[21] = 0x02, 0x00 // длина атрибута меньше его заголовка
	if _, err := parse(badAttr); !errors.Is(err, errMalformed) {
		t.Errorf("атрибут неверной длины: ошибка %v", err)
	}
	if rs, err := parse(nil); err != nil || len(rs) != 0 {
		t.Errorf("пустые данные: %+v, %v", rs, err)
	}
}
