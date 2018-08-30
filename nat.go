package nat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/danderson/nat/stun/stun"
)

// ExchangeCandidatesFun sends/receives Candidates using transport of callers choice.
type ExchangeCandidatesFun func([]byte) []byte

type Config struct {
	// ProbeTimeout is the duration between sending probes. (expected one-way time)
	ProbeTimeout time.Duration
	// ProbeRetry is max attempts we make to get a BindResponse
	ProbeRetry int

	// **TODO** remove next 2 fields here and in DefaultConfig
	// Keep them in until client is updated, since it expects some values.
	// DecisionTime is how much time we wait before checking (on the
	// initiator) all the links that successfully communicated (so they got
	// stun.ClassSuccess in response to a stun.ClassRequest) and deciding
	// which one to use.
	DecisionTime time.Duration
	// PeerDeadline is the duration for which the negotiation must go
	// on. Please note this must be > DecisionTime because after the
	// initiator decided which link to use, we need to have one more
	// complete round-trip (stun.ClassSuccess in response to a
	// stun.ClassRequest) but with UseCandidate set to true.
	PeerDeadline time.Duration
	// Prints all the ongoing handshakes.
	Verbose bool
	// Prints more detail on handshakes and internal state
	Verbose2 bool
	// Bind locally to a specific address.
	BindAddress *net.UDPAddr
	// Which interfaces use for ICE.
	UseInterfaces []string
	// Blacklist given addresses for ICE negotiation.
	BlacklistAddresses []*net.IPNet
	// TOS, if >0, sets IP_TOS to this value. Note an error is considered
	// non-fatal, it is just logged.
	TOS int
}

func DefaultConfig() *Config {
	return &Config{
		ProbeRetry:   3,
		ProbeTimeout: 250 * time.Millisecond,
		DecisionTime: 4 * time.Second,
		PeerDeadline: 6 * time.Second,
		BindAddress:  &net.UDPAddr{},
		TOS:          -1,
	}
}

// ConnectOpt exchanges Candidates and runs engine to open UDP net.Conn.
func ConnectOpt(xchg ExchangeCandidatesFun, initiator bool, cfg *Config) (*Conn, error) {
	sock, err := net.ListenUDP("udp", cfg.BindAddress)
	if err != nil {
		return nil, err
	}
	if err := setTOS(sock, cfg.TOS); err != nil {
		log.Printf("Failed to set TOS to %d: %v", cfg.TOS, err)
	}

	engine := &attemptEngine{
		xchg:      xchg,
		sock:      sock,
		initiator: initiator,
		cfg:       cfg,
	}

	conn, err := engine.run()
	if err != nil {
		sock.Close()
		return nil, err
	}
	return conn, nil
}

func Connect(xchg ExchangeCandidatesFun, initiator bool) (*Conn, error) {
	return ConnectOpt(xchg, initiator, DefaultConfig())
}

type attempt struct {
	candidate           // { Addr *net.UDPAddr, Prio int64 } from gather.go
	tid       [][]byte  // send [n] probes to each candidate
	timeout   time.Time // time to send next probe
	success   bool      // did we get a STUN BindResponse/ClassSuccess from this addr
	chosen    bool      // Use this Candidate (max prio with success after retry)
	retrycnt  int       // number of probes xmited for this candidate
	localaddr net.Addr
}

func (a *attempt) isValidTid(tid []byte) bool {
	len := a.retrycnt // dubious if pkt xmit in other thread
	for try := 0; try < len; try++ {
		if bytes.Equal(tid, a.tid[try]) {
			return true
		}
	}
	return false
}

type attemptEngine struct {
	xchg      ExchangeCandidatesFun
	sock      *net.UDPConn
	initiator bool // true if this party is the initiator/controller ?
	attempts  []attempt
	p2pconn   *Conn // nat.Conn { conn *net.UDPConn } implements net.Conn
	cfg       *Config
	maxPrio   int64    // best Prio amoung all candidates
	likely    *attempt // best successful attempt so far
	likelyP   int64    // priority of likely attempt
	chosen    *attempt // when likely is promoted to chosen: likely.UseCandidate=true
}

func (e *attemptEngine) init() error {
	candidates, err := GatherCandidates(e.sock, e.cfg.UseInterfaces, e.cfg.BlacklistAddresses)
	if err != nil {
		return err
	}

	var peerCandidates []candidate
	jsonCandidates, err := json.Marshal(candidates)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(e.xchg(jsonCandidates), &peerCandidates)
	if err != nil {
		panic(err)
	}

	// At this point, we *should* be making candidate-pairs, with pair-priority and sorting
	// simplified because each party has only 1 local/Base Address
	// todo(jpeck) need to compute combined priority, and sort the CHECK LIST
	// https://tools.ietf.org/html/rfc5245#section-2.3, https://tools.ietf.org/html/rfc5245#section-4.1.2
	e.attempts = make([]attempt, len(peerCandidates))
	for i := range peerCandidates {
		e.attempts[i].candidate = peerCandidates[i]
		e.attempts[i].timeout = time.Time{}
		e.attempts[i].tid = make([][]byte, e.cfg.ProbeRetry)
		e.attempts[i].retrycnt = 0 // < len(e.attempts[i].tid) // max sends to this Candidate.Addr
		if e.maxPrio < e.attempts[i].Prio {
			e.maxPrio = e.attempts[i].Prio
		}
	}

	e.sock.SetWriteDeadline(time.Time{})

	return nil
}

func (e *attemptEngine) xmitOne(attempt *attempt) error {
	tid, err := stun.RandomTid()
	if err != nil {
		return err
	}
	packet, err := stun.BindRequest(tid, nil, false, attempt.chosen)
	if err != nil {
		return err
	}
	// even if write fails, record a 'valid' TID for this try
	attempt.tid[attempt.retrycnt] = tid
	// even if write fails, count it as an attempt:
	attempt.retrycnt++
	if e.cfg.Verbose {
		log.Printf("TX [%x] #%d to %v (chosen %v) %v", tid, attempt.retrycnt, attempt.Addr, attempt.chosen, time.Now())
	}
	_, err = e.sock.WriteToUDP(packet, attempt.Addr)
	attempt.timeout = time.Now().Add(e.cfg.ProbeTimeout)
	return err
}

// transmit all the useful attempts.
// return the next timeout of the all the xmit'd attempts.
// or an error if anything failed.
func (e *attemptEngine) xmit() (time.Time, error) {
	now := time.Now()
	var ret time.Time
	var attempt *attempt // current attempt

	// Note: this is NOT ICE [rfc8445, rfc5245]
	for i := range e.attempts {
		attempt = &e.attempts[i]
		// Note: e.likelyP ~= (e.likely != nil ? e.likely.Prio : -1)
		// do not resend (& wait for) successful or lower priority probes
		// Note: Ok to resend the chosen attempt (to inform responder)
		if attempt.retrycnt < len(attempt.tid) && attempt.timeout.Before(now) &&
			(attempt.chosen || (!attempt.success && attempt.Prio > e.likelyP)) {
			// send new BindRequest:
			// select lowest timeout value of xmit'd packet: [ >= now+ProbeTimout ]
			err := e.xmitOne(attempt)
			if err != nil && e.cfg.Verbose {
				// failure to send probes is not fatal, just log it:
				log.Printf("failed to xmit packet: %v", err)
			}
		}
		if (ret.IsZero() || attempt.timeout.Before(ret)) && attempt.timeout.After(now) {
			ret = attempt.timeout
		}
	}
	if ret.IsZero() && e.cfg.Verbose {
		log.Printf("No outstanding attempts")
	}
	return ret, nil
}

// maybe set p2pconn;
// for BindRequest:
//  send BindResponse;
//  maybe set p2pconn:
//    if !initiator && BindRequest.UseCandidate for a .success candidate/attempt.
// for BindResponse:
//  maybe set p2pconn:
//    if initiator  && BindResponse for a .chosen candidate/attempt
//  else if !blacklist; set .success

func (e *attemptEngine) read() error {
	buf := make([]byte, 512)
	n, from, err := e.sock.ReadFromUDP(buf)
	if err != nil {
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			return nil
		}
		return err
	}

	packet, err := stun.ParsePacket(buf[:n], nil)
	if err != nil {
		if e.cfg.Verbose {
			log.Printf("Cannot parse packet from %v: %v", from, err)
		}
		// just ignore this buf; in the real world, stream { n, buf[:n], from } to port mux chan
		return nil
	}

	if packet.Method != stun.MethodBinding {
		if e.cfg.Verbose {
			log.Printf("Packet from %v is not a binding request", from)
		}
		return nil
	}

	switch packet.Class {
	case stun.ClassRequest: // received a probe from other side, reply with BindResponse
		if e.cfg.Verbose {
			log.Printf("RX/TX [%x] from %v ClassRequest (use candidate %v)", packet.Tid[:], from, packet.UseCandidate)
		}
		response, err := stun.BindResponse(packet.Tid[:], from, nil, false)
		if err != nil {
			if e.cfg.Verbose {
				log.Printf("BindResponse failed for [%x] from %v: %v", packet.Tid[:], from, err)
			}
			return nil
		}
		// send response (ClassSuccess)
		_, err = e.sock.WriteToUDP(response, from)
		if err != nil {
			log.Printf("WriteToUDP failed to write response %v: %v", response, err)
			return nil // initiator will retry this probe
		}
		if packet.UseCandidate && !e.initiator {
			// *USE* this candidate! initiator has found mutual success. stop dorking around...
			// find the attempt:
			for i := range e.attempts {
				attempt := &e.attempts[i]
				if from.String() != attempt.Addr.String() {
					continue
				}
				// assumes only one attempt has this remote Addr/Candidate
				// mostly ok: we only have/use 1 local address
				if !attempt.success {
					// complain if told to use a Candidate that does not have .success
					m := fmt.Errorf("bad link: local %v remote %v", attempt.localaddr, attempt.Addr)
					if e.cfg.Verbose {
						log.Printf("Error: %v", m)
					}
					return m
				}
				if e.p2pconn == nil {
					if e.cfg.Verbose {
						log.Printf("Confirmed local %v remote %v", attempt.localaddr, attempt.Addr)
					}
					e.p2pconn = newConn(e.sock, attempt.localaddr, attempt.Addr)
				}
				return nil // ICE is done...
			}
		}

	case stun.ClassSuccess: // a BindResponse indicating a successful round trip; mark attempts[i].success = true
		if e.cfg.Verbose {
			log.Printf("RX [%x] from %v ClassSuccess (use candidate %v)", packet.Tid[:], from, packet.UseCandidate)
		}
		// we have packet; which (valid) attempt was it?
		for i := range e.attempts {
			attempt := &e.attempts[i]
			if !attempt.isValidTid(packet.Tid[:]) {
				continue
			}
			// tid indicates we have found the attempt
			if e.cfg.Verbose2 {
				log.Printf("ClassSuccess: try matching attempts[%d] %s (chosen %v)", i, attempt.Addr.String(), attempt.chosen)
			}
			if from.String() != attempt.Addr.String() {
				if e.cfg.Verbose2 {
					log.Printf("ClassSuccess: [%x] Addr mismatch %s != %s", packet.Tid[:], from.String(), attempt.Addr.String())
				}
				return nil
			}
			if e.initiator && attempt.chosen {
				// responder is ack'ing after UseCandidate (all prior attempts were invalidated)
				if e.p2pconn == nil {
					if e.cfg.Verbose {
						log.Printf("ClassSuccess: Confirmed local %v remote %v", attempt.localaddr, attempt.Addr)
					}
					e.p2pconn = newConn(e.sock, attempt.localaddr, attempt.Addr)
				} else {
					if e.cfg.Verbose2 {
						log.Printf("ClassSuccess: Already connected! ep2pconn=%v", e.p2pconn)
					}
				}
				return nil // already success and chosen and p2pconn: we are done.
			}
			if e.cfg.Verbose2 {
				log.Printf("ClassSuccess: attempts[%d].success=true .localaddr=%v .Prio=%x, from=%v", i, packet.Addr, attempt.Prio, from)
			}
			attempt.success = true
			attempt.localaddr = packet.Addr
			// update the likely best candidate:
			if e.likelyP < attempt.Prio {
				e.likelyP = attempt.Prio
				e.likely = attempt
				if e.cfg.Verbose2 {
					log.Printf("likely candidate: Addr=%v Prio=%x", attempt.Addr, attempt.Prio)
				}
			}
			return nil
		}
	}

	return nil
}

// xmit probes for a while...
// then decide() if there is a .success, set .chosen=true
//      then xmit with .UseCandidate=true
//

func (e *attemptEngine) run() (*Conn, error) {
	if err := e.init(); err != nil {
		return nil, err
	}
	if e.cfg.Verbose {
		pto := "--ice_probe_timeout=" + fmt.Sprintf("%dms", (e.cfg.ProbeTimeout).Nanoseconds()/1000000)
		dt := " --ice_probe_retry=" + fmt.Sprintf("%d", e.cfg.ProbeRetry)
		vb := " --ice_verbose=" + fmt.Sprintf("%v", (e.cfg.Verbose))
		vb2 := "--ice_verbose2=" + fmt.Sprintf("%v", (e.cfg.Verbose2))
		in := " initator=" + fmt.Sprintf("%v", e.initiator)
		log.Printf("nat.go start: %v ", time.Now())
		log.Printf("nat.go ICE config: %s %s %s %s %s", pto, dt, vb, vb2, in)
	}

	endTime := time.Time{}

	// run until break or return
	for e.p2pconn == nil {
		// xmit all the useful probes, see if there are probes to wait for:
		timeout, err := e.xmit()
		if err != nil {
			if e.cfg.Verbose {
				log.Printf("TX failed: %v", err)
			}
			return nil, err // presumably, network or system errors; give up.
		}
		if timeout.IsZero() {
			if e.initiator {
				// no more probes/responses to wait for
				if e.chosen != nil {
					m := fmt.Errorf("failed with UseCandidate=true for %v", e.chosen)
					if e.cfg.Verbose {
						log.Printf("%v", m)
					}
					return nil, m
				}
				// select the attempt:
				if err := e.decide(); err != nil {
					if e.cfg.Verbose {
						log.Printf("Decision failed: %v", err)
					}
					return nil, err
				}
				// decide will restart the chosen attempt; keep running until p2pconn is set up
				// e.read() will immediately timeout, and loop to xmit
			} else {
				if endTime.IsZero() {
					// eventually, stop waiting for probe.UseCand from initiator...
					dt := time.Duration(e.cfg.ProbeTimeout.Nanoseconds() * int64(e.cfg.ProbeRetry))
					endTime = time.Now().Add(dt)
					if e.cfg.Verbose2 {
						log.Printf("Will wait only until %v", endTime)
					}
				}
				if time.Now().After(endTime) {
					return nil, errors.New("No feasible connection to peer")
				}
			}
			timeout = time.Now().Add(e.cfg.ProbeTimeout)
		}

		if e.cfg.Verbose2 {
			log.Printf("SetReadDeadline: %v", timeout)
		}
		e.sock.SetReadDeadline(timeout)
		if err = e.read(); err != nil {
			if e.cfg.Verbose {
				log.Printf("RX failed: %v", err)
			}
			return nil, err
		}
		if e.cfg.Verbose2 {
			log.Printf("e.read done or timeout Now: %v", time.Now())
		}
	}

	// Time is up, a decision has been made... and read has set a p2pconn
	if e.cfg.Verbose {
		log.Printf("nat.go Success!: %v ", time.Now())
	}
	return e.p2pconn, nil // we have a p2pconn, use it...
}

// set .chosen where .success and max(.Prio)
func (e *attemptEngine) decide() error {
	if e.likely == nil {
		return errors.New("No feasible connection to peer")
	}
	if e.cfg.Verbose {
		log.Printf("decide: local %v remote %v likelyP=%x (best=%x)",
			e.likely.localaddr, e.likely.Addr, e.likelyP, e.maxPrio)
	}
	// We need one final exchange over the chosen connection, to
	// indicate to the peer that we've picked this one. That's why we
	// expire whatever timeout there is here and now.
	e.chosen = e.likely
	e.chosen.chosen = true
	e.chosen.timeout = time.Time{}
	e.chosen.retrycnt = 0 // start over...don't need to match any of the old TIDs
	return nil
}
