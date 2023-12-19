/*
 * VC5 load balancer. Copyright (C) 2021-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package mon

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

var client *http.Client

func init() {
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 1 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	client = &http.Client{
		Timeout:   time.Second * 3,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol uint8
}

type Destination struct {
	Address netip.Addr
	Port    uint16
}

type scheme bool

const (
	GET  method = false
	HEAD method = true
	UDP  method = false
	TCP  method = true
)

type Instance struct {
	Service     Service
	Destination Destination
}

type Services map[Instance]Checks

// type Foo struct {
type Foo = Target
type Target struct {
	Init   bool
	Checks Checks
}

type state struct {
	mutex  sync.Mutex
	checks chan Checks
	status status
}

type status = Status
type Status struct {
	OK          bool
	Diagnostic  string
	Time        time.Duration
	Last        time.Time
	When        time.Time
	Initialised bool
}

type Mon struct {
	C        chan bool
	services map[Instance]*state
	syn      *SYN
	prober   Prober
}

func New(addr netip.Addr, services map[Instance]Foo, p Prober) (*Mon, error) {

	m := &Mon{C: make(chan bool, 1), services: make(map[Instance]*state), prober: p}

	if m.prober == nil {
		m.prober = prober{m: m}
	}

	var err error
	m.syn, err = Syn(addr, false)

	if m.syn == nil {
		return nil, err
	}

	m.Update(services)

	return m, nil
}

func (m *Mon) Status(svc Service, dst Destination) (status Status, _ bool) {
	s, ok := m.services[Instance{Service: svc, Destination: dst}]

	if !ok {
		return status, ok
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.status, ok
}

func (m *Mon) Dump() map[Instance]Status {

	r := map[Instance]Status{}

	for k, v := range m.services {
		v.mutex.Lock()
		r[k] = v.status
		v.mutex.Unlock()
	}

	return r
}

func (m *Mon) Stop() {
	m.Update(nil)
}

func (m *Mon) Update(checks map[Instance]Foo) {

	for instance, state := range m.services {
		if new, ok := checks[instance]; ok {
			state.checks <- new.Checks
			delete(checks, instance)
		} else {
			close(state.checks) // no longer exists
			delete(m.services, instance)
		}
	}

	for instance, c := range checks {
		state := &state{status: status{OK: c.Init, Diagnostic: "Initialising ..."}}
		state.checks = m.monitor(instance.Service.Address, instance.Destination.Address, instance.Destination.Port, state, c.Checks)
		m.services[instance] = state
	}

	select {
	case m.C <- true:
	default:
	}
}

// need to add some sort of history, 4-out-of-5 or something
// start with service ok:  history[1 1 1 1 0]
// rotate to: history[1 1 1 0 x]
// first check either keeps service ok, or marks it as down
// once down then all last 5 checks need to pass to bring back up

func (m *Mon) monitor(vip, rip netip.Addr, port uint16, state *state, c Checks) chan Checks {
	C := make(chan Checks, 10)

	go func() {

		history := [5]bool{true, true, true, true, false}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			var ok bool
			select {
			case <-ticker.C:
				state.mutex.Lock()
				was := state.status
				state.mutex.Unlock()

				now := was

				t := time.Now()

				ok, now.Diagnostic = m.Probes(vip, rip, port, c)

				copy(history[0:], history[1:])
				history[4] = ok

				//fmt.Println("HISTORY:", history, "XXXXXXXXXXXXXXXXXXXX", ok, now.Diagnostic)

				var passed int
				for _, v := range history {
					if v {
						passed++
					}
				}

				if was.OK {
					if passed < 4 {
						now.OK = false
					}
				} else {
					if passed > 4 {
						now.OK = true
					}
				}

				now.Last = t
				now.Time = time.Now().Sub(t)
				now.Initialised = true

				state.mutex.Lock()
				state.status = now
				state.mutex.Unlock()

				if !was.Initialised || was.OK != now.OK {
					//if was.OK != now.OK {
					now.When = t
					select {
					case m.C <- true:
					default:
					}
				}

			case c, ok = <-C:
				if !ok {
					return
				}
			}
		}
	}()

	return C
}

type Checks = []Check
type Check struct {
	//Type string `json:"type,omitempty"`
	Type string `json:"type,omitempty"`

	// TCP/UDP port to use for L4/L7 checks
	Port uint16 `json:"port,omitempty"`

	// HTTP Host header to send in healthcheck
	Host string `json:"host,omitempty"`

	// Path of resource to use when building a URI for HTTP/HTTPS healthchecks
	Path string `json:"path,omitempty"`

	// Expected HTTP status codes to allow check to succeed
	Expect []int `json:"expect,omitempty"`

	// Method - HTTP: GET=false, HEAD=true DNS: UDP=false TCP=true
	Method bool `json:"method,omitempty"`
}

type method = bool

type Prober interface {
	Probe(netip.Addr, netip.Addr, Check) (bool, string)
	//Resets() bool
}

type prober struct {
	m *Mon
}

// func (p prober) Resets() bool { return false }
func (p prober) Probe(vip, rip netip.Addr, check Check) (bool, string) {
	return p.m.Probe(vip, rip, check)
}

func (m *Mon) Probes(vip, rip netip.Addr, port uint16, checks Checks) (bool, string) {
	for _, c := range checks {

		if c.Port == 0 {
			c.Port = port
		}

		ok, s := m.prober.Probe(vip, rip, c)

		//fmt.Println("RESULT:", ok, s)

		if !ok {
			return ok, c.Type + ": " + s
		}
	}

	return true, "OK"
}

func (m *Mon) Probe(vip, addr netip.Addr, c Check) (ok bool, s string) {
	switch c.Type {
	case "http":
		ok, s = m.HTTP(addr, c.Port, false, c.Method, c.Host, c.Path, c.Expect...)
	case "https":
		ok, s = m.HTTP(addr, c.Port, true, c.Method, c.Host, c.Path, c.Expect...)
	case "syn":
		ok, s = m.SYN(addr, c.Port)
	case "dns":
		ok, s = m.DNS(addr, c.Port, c.Method)
	default:
		s = "Unknown check type"
	}

	return
}

func (m *Mon) DNS(addr netip.Addr, port uint16, useTCP bool) (bool, string) {

	if useTCP {
		return dnstcp(addr.String(), port)
	}

	return dnsudp(addr.String(), port)
}

func (m *Mon) SYN(addr netip.Addr, port uint16) (bool, string) {

	if !addr.Is4() {
		return false, "Not an IPv4 address"
	}

	ip := addr.As4()

	return m.syn.Check(ip, port)
}

func (m *Mon) HTTP(addr netip.Addr, port uint16, https bool, head bool, host, path string, expect ...int) (bool, string) {
	defer client.CloseIdleConnections()

	if port == 0 {
		return false, "Port is 0"
	}

	scheme := "http"
	method := "GET"

	if https {
		scheme = "https"
	}

	if head {
		method = "HEAD"
	}

	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	url := fmt.Sprintf("%s://%s:%d/%s", scheme, addr, port, path)
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		return false, err.Error()
	}

	if host != "" {
		req.Host = host
	}

	resp, err := client.Do(req)

	if err != nil {
		return false, err.Error()
	}

	defer resp.Body.Close()

	ioutil.ReadAll(resp.Body)

	if len(expect) == 0 {
		return resp.StatusCode == 200, resp.Status
	}

	for _, e := range expect {
		if resp.StatusCode == e {
			return true, resp.Status
		}
	}
	return false, resp.Status
}

// unlikely, but may need to override for SNI in case remote server selects handler based on TLS values?
// something like: https://github.com/golang/go/issues/22704
/*
dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
	DualStack: true,
}

client := http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// redirect all connections to 127.0.0.1
			addr = "127.0.0.1" + addr[strings.LastIndex(addr, ":"):]
			return dialer.DialContext(ctx, network, addr)
		},
	},
}
*/

// create a new client each time, with right IP?
