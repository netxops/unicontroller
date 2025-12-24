package sup

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/smallnest/ringbuffer"
)

type peer struct {
	mutex sync.Mutex
	w     io.Writer
	ok    bool
}

type Fanout struct {
	mutex      sync.Mutex
	source     io.Reader
	ring       *ringbuffer.RingBuffer
	readerList []*peer
}

func NewFanout(source io.Reader) *Fanout {
	f := &Fanout{
		source: source,
		ring:   ringbuffer.New(4096 * 100),
	}
	go f.start()
	go f.out()
	return f
}

func (f *Fanout) start() error {
	for {
		_, err := io.CopyN(f.ring, f.source, 1)
		if err != nil && err != io.EOF {
			fmt.Println("fanout.start, ", err)
			err = fmt.Errorf("failed to copy data from source to ring buffer, err: %s", err)
			fmt.Println(err)
			return err
		}
	}
}

func (f *Fanout) out() error {
	buf := make([]byte, 1)
	for {
		max := f.ring.Length()
		if max == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		count := 0

		m, err := f.ring.Read(buf)
		if err != nil && err != io.EOF {
			// fmt.Println("fantout.out:", err)
			err = fmt.Errorf("failed to read data from ring buffer, err: %s", err)
			fmt.Println(err)
			return err
		}

		f.mutex.Lock()
		for _, peer := range f.readerList {
			n, err := peer.w.Write(buf[0:m])
			count = count + n
			if err != nil && err != io.EOF {
				peer.mutex.Lock()
				peer.ok = false
				peer.mutex.Unlock()
				fmt.Println(err)
			}
		}
		f.mutex.Unlock()
	}
}

func (f *Fanout) NewReader() io.Reader {
	pr, pw := io.Pipe()
	r := &peer{
		w:  pw,
		ok: true,
	}
	// go r.start()

	f.mutex.Lock()
	f.mutex.Unlock()
	f.readerList = append(f.readerList, r)

	return pr
}
