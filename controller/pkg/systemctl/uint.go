package systemctl

import (
	"bytes"
	"io"
)

func Serialize(opts []UnitOption) io.Reader {
	var buf bytes.Buffer
	if len(opts) == 0 {
		return &buf
	}
	idx := map[string][]UnitOption{}
	var sections []string
	for _, opt := range opts {
		sec := opt.Section
		if _, ok := idx[sec]; !ok {
			sections = append(sections, sec)
		}
		idx[sec] = append(idx[sec], opt)
	}

	for i, sect := range sections {
		writeSectionHeader(&buf, sect)
		writeNewline(&buf)

		opts := idx[sect]
		for _, opt := range opts {
			writeOption(&buf, &opt)
			writeNewline(&buf)
		}
		if i < len(sections)-1 {
			writeNewline(&buf)
		}
	}

	return &buf
}

func writeNewline(buf *bytes.Buffer) {
	buf.WriteRune('\n')
}

func writeSectionHeader(buf *bytes.Buffer, section string) {
	buf.WriteRune('[')
	buf.WriteString(section)
	buf.WriteRune(']')
}

func writeOption(buf *bytes.Buffer, opt *UnitOption) {
	buf.WriteString(opt.Name)
	buf.WriteRune('=')
	buf.WriteString(opt.Value)
}
