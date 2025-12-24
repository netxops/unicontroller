package jsonp

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
)

func ReadMessage(c net.Conn) ([]byte, error) {
	l := make([]byte, 2) // takes the first two bytes: the Length Message.
	i, err := c.Read(l)  // read the bytes.
	if err != nil {
		return nil, err
	}

	lm := binary.BigEndian.Uint16(l[:i]) // convert the bytes into int16.

	b := make([]byte, lm) // create the byte buffer for the body.
	e, err := c.Read(b)   // read the bytes.
	if err != nil && err != io.EOF {
		return nil, errors.New("error encountered while reading data")
	}

	if e != int(lm) {
		return nil, errors.New("inadequate data received, data format error")
	}

	return b[:e], nil // returns the body
}

func WriteMessage(m []byte, c net.Conn) {
	l := make([]byte, 2)                          // creates the Length Message buffer.
	binary.BigEndian.PutUint16(l, uint16(len(m))) // Converts len to bytes.
	c.Write(append(l, m...))                      // send the message
}

func ReadJSON(c net.Conn, a any) error {
	msg, err := ReadMessage(c)
	if err != nil {
		return err
	}
	return json.Unmarshal(msg, a)
}

func SendJSON(c net.Conn, a any) error {
	msg, err := json.Marshal(a)

	if err != nil {
		return err
	}

	WriteMessage(msg, c)
	return nil
}
