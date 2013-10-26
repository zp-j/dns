// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !appengine

// Rate limit implementation.

package dns

import (
	"net"
	"time"
	"hash/adler32"
)

// Ratelimiter is enforced in the WriteMsg method, calling Write directly will bypass any
// ratelimiting.
type Ratelimiter interface {
	// Count counts against this remote address with this
	// request and this reply packet. Count should be called in your handler function.
	Count(remote net.Addr, req, reply *Msg)
	// Blocked returns a integer which tells if this reply should be dropped (-1), a
	// a normal reply should be send back to the client (1) or a truncated answer
	// should be send back (1).
	Block(remote net.Addr, reply *Msg) int
}


const (
	WINDOW = 5
	BUCKETSIZE = 10000
	LIMIT = 50
)

type bucket struct {
	source net.Addr  // client address
	stamp  time.Time // time of last count update
	rate   int       // rate of the queries for this client, in qps
	count  int       // number of requests seen in the last secnd
}

type request struct {
	a net.Addr
	q *Msg
	r *Msg
}

type blocker struct {
	block [BUCKETSIZE]*bucket
	ch    chan *request
}

// serialize the writing.
func (b *blocker) blockerUpdate() {
	offset := 0
	for {
		select {
		case r := <-b.ch:
			if t, ok := r.a.(*net.UDPAddr); ok {
				offset = int(adler32.Checksum(t.IP) % BUCKETSIZE)
			}
			if t, ok := r.a.(*net.TCPAddr); ok {
				offset = int(adler32.Checksum(t.IP) % BUCKETSIZE)
			}
			if b.block[offset] == nil { // re-initialize if source differs?
				b.block[offset] = &bucket{r.a, time.Now(), 0, 1}
				continue
			}
			if time.Since(b.block[offset].stamp) < time.Second {
				b.block[offset].stamp = time.Now()
				b.block[offset].count++
				b.block[offset].rate = b.block[offset].count
				continue
			}
			if time.Since(b.block[offset].stamp) > WINDOW*time.Second {
				b.block[offset].stamp = time.Now()
				b.block[offset].rate = 0
				b.block[offset].count = 1
				continue
			}
			b.block[offset].rate >>= uint(time.Since(b.block[offset].stamp).Seconds())
			b.block[offset].rate += b.block[offset].count
			b.block[offset].stamp = time.Now()
			b.block[offset].count = 1
		}
	}
}

func (b *blocker) Count(a net.Addr, q, r *Msg) {
	b.ch <- &request{a, q, r}
}

func (b *blocker) Block(a net.Addr, q *Msg) int {
	offset := 0
	if t, ok := a.(*net.UDPAddr); ok {
		offset = int(adler32.Checksum(t.IP) % BUCKETSIZE)
	}
	if t, ok := a.(*net.TCPAddr); ok {
		offset = int(adler32.Checksum(t.IP) % BUCKETSIZE)
	}
	if b.block[offset] == nil {
		return 0
	}
	if b.block[offset].rate > LIMIT {
		println("HITTING LIMIT, THROTTLING")
		return -1
	}
	return 0
}
