// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !appengine

// Rate limit implementation.

// RATE LIMITING
//
// Limiting the rate of responses by a
// DNS server is used in order to blunt the impact of DNS reflection and
// amplification attacks.
//
// Basic use pattern for setting up a server with rate limiting:
//
//	b := dns.NewResponseRatelimit()
//	go func() {
//		srv := &dns.Server{Addr: ":8053", Net: "udp", Ratelimiter: b}
//		err := srv.ListenAndServe()
//		if err != nil {
//			log.Fatal("Failed to set tcp listener %s\n", err.Error())
//		}
//	}()
//
package dns

import (
	"hash/adler32"
	"log"
	"net"
	"time"
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

// NewResponseRatelimit returns an Ratelimiter which is an implementation of
// response rate limit (RRL) with good defaults.
// See http://ss.vix.su/~vixie/isc-tn-2012-1.txt for an explanation of the
// these defaults.
func NewResponseRatelimit() *ResponseRatelimit {
	b := &ResponseRatelimit{Window: 5, ResponsesPerSecond: 5, ErrorsPerSecond: 5, IPv4PrefixLen: 24, IPv6PrefixLen: 56, LeakRate: 3, TruncateRate: 2}
	b.serialize = make(chan *item, BUCKETSIZE)
	go b.count()
	return b
}

const BUCKETSIZE = 10000

type rrlBucket struct {
	source net.Addr  // client address
	stamp  time.Time // time of last count update
	rate   int       // rate of the queries for this client, in qps
	count  int       // number of requests seen in the last second
}

type item struct {
	a net.Addr
	q *Msg
	r *Msg
}

type ResponseRatelimit struct {
	block              [BUCKETSIZE]*rrlBucket
	serialize          chan *item
	Window             time.Duration
	ResponsesPerSecond int
	ErrorsPerSecond    int
	LeakRate           int
	TruncateRate       int
	IPv4PrefixLen      int
	IPv6PrefixLen      int
	LogOnly            *log.Logger // if not nil, do nothing, but log via this Logger.
}

func (b *ResponseRatelimit) count() {
	offset := 0
	for {
		select {
		case r := <-b.serialize:
			if t, ok := r.a.(*net.UDPAddr); ok {
				offset = int(adler32.Checksum(t.IP) % BUCKETSIZE)
			}
			if t, ok := r.a.(*net.TCPAddr); ok {
				offset = int(adler32.Checksum(t.IP) % BUCKETSIZE)
			}
			if b.block[offset] == nil { // re-initialize if source differs?
				b.block[offset] = &rrlBucket{r.a, time.Now(), 0, 1}
				continue
			}
			if time.Since(b.block[offset].stamp) < time.Second {
				b.block[offset].stamp = time.Now()
				b.block[offset].count++
				b.block[offset].rate = b.block[offset].count
				continue
			}
			if time.Since(b.block[offset].stamp) > b.Window*time.Second {
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

func (b *ResponseRatelimit) Count(a net.Addr, q, r *Msg) {
	b.serialize <- &item{a, q, r}
}

func (b *ResponseRatelimit) Block(a net.Addr, q *Msg) int {
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
	if b.block[offset].rate > 50 {
		if b.LogOnly != nil {
			b.LogOnly.Printf("client `%s': blocking")
			return 0
		}
		return -1
	}
	return 0
}

// NewBandwidthRatelimit returns an Ratelimiter which is an implementation of
// bandwith rate limit (RRL). TODO(miek): docs
func NewBandwidthRatelimit() *BandwidthRatelimit {
	return nil
}

type bwBucket struct {
	source    net.Addr  // client address
	stamp     time.Time // time of last count update
	bandwidth int       // bandwidth send to client, in bytes per second
}

type BandwidthRatelimit struct {
	block     [BUCKETSIZE]*bwBucket
	serialize chan *item
	Window    time.Duration
}
