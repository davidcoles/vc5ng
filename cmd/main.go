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

package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/davidcoles/vc5ng"
	"github.com/davidcoles/vc5ng/bgp"
	"github.com/davidcoles/vc5ng/mon"
	"github.com/davidcoles/xvs"
)

//go:embed static/*
var STATIC embed.FS

type Client = xvs.Client

func main() {
	var mutex sync.Mutex

	start := time.Now()
	logger := logger{}

	sock := flag.String("s", "", "socket")
	native := flag.Bool("n", false, "Native mode XDP")
	redirect := flag.Bool("r", false, "Redirect mode")

	flag.Parse()

	args := flag.Args()

	if *sock != "" {
		// we're going to be the server running in the network namespace ...
		signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
		netns(*sock, netip.MustParseAddr(args[0]))
		return
	}

	socket, err := ioutil.TempFile("/tmp", "vc5ns")

	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(socket.Name())

	file := args[0]
	addr := netip.MustParseAddr(args[1])
	nics := args[2:]

	if !addr.Is4() {
		log.Fatal("Address is not IPv4: ", addr)
	}

	config, err := Load(file)

	if err != nil {
		log.Fatal(err)
	}

	client := &Client{
		Interfaces: nics,
		Address:    addr,
		Redirect:   *redirect,
		Native:     *native,
		VLANs:      config.VLANs(),
		NAT:        true,
		Logger:     logger,
	}

	err = client.Start()

	if err != nil {
		log.Fatal(err)
	}

	pool := bgp.NewPool(addr.As4(), config.BGP, nil)

	if pool == nil {
		log.Fatal("BGP pool fail")
	}

	go spawn(client.Namespace(), os.Args[0], "-s", socket.Name(), client.NamespaceAddress())

	af_unix := unix(socket.Name())

	director := &vc5ng.Director{
		Logger: logger,
		Balancer: &Balancer{
			Client: client,
			ProbeFunc: func(addr netip.Addr, check mon.Check) (bool, string) {
				return probe(af_unix, addr, check)
			},
		},
	}

	err = director.Start(config.Services.parse())

	if err != nil {
		log.Fatal(err)
	}

	done := make(chan bool)

	rib := director.RIB()
	vip := map[netip.Addr]State{}

	var summary Summary

	services, old, serviceState, _ := serviceStatus(config, client, director, nil, nil)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			mutex.Lock()
			summary.xvs(client.Info(), summary)
			summary.Uptime = uint64(time.Now().Sub(start) / time.Second)
			services, old, serviceState, summary.Current = serviceStatus(config, client, director, old, serviceState)
			mutex.Unlock()
			select {
			case <-ticker.C:
			case <-done:
				return
			}
		}
	}()

	go func() { // advertise VIPs via BGP
		timer := time.NewTimer(5 * time.Second)
		ticker := time.NewTicker(3 * time.Second)
		old := map[netip.Addr]time.Time{}

		var init bool
		for {
			select {
			case _, ok := <-director.C:
				if !ok {
					return
				}
			case <-ticker.C:
			case <-timer.C:
				fmt.Println("STARTS")
				init = true
			}

			{
				rib := map[netip.Addr]bool{}
				new := map[netip.Addr]State{}

				for _, v := range director.RIB() {
					rib[v] = true
				}

				for _, s := range director.Status() {
					v := s.Address

					if o, ok := vip[v]; ok {
						up, _ := rib[v]

						if o.up != up {
							new[v] = State{up: up, time: time.Now()}
						} else {
							new[v] = o
						}

					} else {
						new[v] = State{up: rib[v], time: time.Now()}
					}
				}

				mutex.Lock()
				vip = new
				mutex.Unlock()
			}

			if init {
				new := map[netip.Addr]time.Time{}
				now := time.Now()
				var out []netip.Addr

				// VIP needs to be up for at least 5 seconds to be advertised
				for _, ip := range director.RIB() {
					if t, exists := old[ip]; exists {
						if now.Sub(t) > (5 * time.Second) {
							out = append(out, ip)
						}
						new[ip] = t
					} else {
						new[ip] = now
					}
				}

				old = new

				//fmt.Println("RIB:", rib)
				mutex.Lock()
				rib = out
				pool.RIB(rib)
				mutex.Unlock()
			}
		}
	}()

	fmt.Println("******************** RUNNING ********************")

	static := http.FS(STATIC)
	//var fs http.FileSystem

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "static/" + r.URL.Path
		http.FileServer(static).ServeHTTP(w, r)
	})

	http.HandleFunc("/prefixes.json", func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		p := client.Prefixes()
		fmt.Println(time.Now().Sub(t))
		js, _ := json.Marshal(&p)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		js, err := json.MarshalIndent(config, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		status := director.Status()
		js, err := json.MarshalIndent(&status, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/xvs", func(w http.ResponseWriter, r *http.Request) {
		var ret []interface{}
		type status struct {
			Service      xvs.ServiceExtended
			Destinations []xvs.DestinationExtended
		}
		svcs, _ := client.Services()
		for _, se := range svcs {
			dsts, _ := client.Destinations(se.Service)
			ret = append(ret, status{Service: se, Destinations: dsts})
		}
		js, err := json.MarshalIndent(&ret, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {

		mutex.Lock()
		metrics := prometheus(services, summary, vip)
		mutex.Unlock()

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Join(metrics, "\n") + "\n"))
	})
	http.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		type status struct {
			Services map[VIP][]Serv        `json:"services"`
			Summary  Summary               `json:"summary"`
			VIP      []VIPStats            `json:"vip"`
			BGP      map[string]bgp.Status `json:"bgp"`
			RIB      []netip.Addr          `json:"rib"`
		}

		mutex.Lock()
		js, err := json.MarshalIndent(&status{
			Services: services,
			Summary:  summary,
			VIP:      vipStatus(services, rib),
			BGP:      pool.Status(),
			RIB:      rib,
		}, " ", " ")
		mutex.Unlock()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	go func() {
		log.Fatal(http.ListenAndServe(":80", nil))
	}()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGQUIT:
			fmt.Println("CLOSING")
			close(done)
			pool.Close()
			time.Sleep(time.Second)
			director.Stop()
			time.Sleep(time.Second)
			fmt.Println("DONE")
			return
		case syscall.SIGINT:
			conf, err := Load(file)
			if err == nil {
				mutex.Lock()
				config = conf
				client.UpdateVLANs(config.VLANs())
				director.Configure(config.Services.parse())
				pool.Configure(config.BGP)
				mutex.Unlock()
			} else {
				log.Println(err)
			}
		}
	}
}

type query struct {
	Addr  string    `json:"addr"`
	Check mon.Check `json:"check"`
}

type reply struct {
	OK         bool   `json:"ok"`
	Diagnostic string `json:"diagnostic"`
}

func probe(client *http.Client, addr netip.Addr, check mon.Check) (bool, string) {

	q := query{Addr: addr.String(), Check: check}

	buff := new(bytes.Buffer)
	err := json.NewEncoder(buff).Encode(&q)

	if err != nil {
		return false, "Internal error marshalling probe: " + err.Error()
	}

	resp, err := client.Post("http://unix/probe", "application/octet-stream", buff)

	if err != nil {
		return false, "Internal error contacting netns daemon: " + err.Error()
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var r reply

	err = json.Unmarshal(body, &r)

	if err != nil {
		r.Diagnostic = "unable to unmarshal reply: " + err.Error()
	}

	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("%d response: %s", resp.StatusCode, r.Diagnostic)
	}

	return r.OK, r.Diagnostic
}

// spawn a server (specified by args) which runs in the network namespace - if it dies then restart it
func spawn(netns string, args ...string) {
	for {
		cmd := exec.Command("ip", append([]string{"netns", "exec", netns}, args...)...)
		_, _ = cmd.StdinPipe()
		stderr, _ := cmd.StderrPipe()
		stdout, _ := cmd.StdoutPipe()

		reader := func(s string, fh io.ReadCloser) {
			scanner := bufio.NewScanner(fh)
			for scanner.Scan() {
				fmt.Println("NETNS:", s, scanner.Text())
			}
		}

		go reader("stderr", stderr)

		if err := cmd.Start(); err != nil {
			log.Println("Daemon", err)
		} else {
			reader("stdout", stdout)

			if err := cmd.Wait(); err != nil {
				log.Println("Daemon", err)
			}
		}

		time.Sleep(1 * time.Second)
	}
}

// server to run in the network namespace - receive probes from unix socket, pass to the 'mon' object to execute
func netns(socket string, addr netip.Addr) {

	go func() {
		// if stdin is closed (parent dies) then exit
		reader := bufio.NewReader(os.Stdin)
		_, _, err := reader.ReadRune()

		if err != nil {
			os.Remove(socket)
			log.Fatal(err)
		}
	}()

	monitor, err := mon.New(addr, nil, nil, logger{})

	if err != nil {
		log.Fatal(err)
	}

	os.Remove(socket)

	s, err := net.Listen("unix", socket)

	if err != nil {
		log.Fatal(err)
	}

	// temporary for testing purposes
	os.Remove("/tmp/vc5ns")
	os.Symlink(socket, "/tmp/vc5ns")

	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {

		body, err := ioutil.ReadAll(r.Body)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"ok":false,"diagnostic":"unable to read request body"}`))
			return
		}

		var q query

		err = json.Unmarshal(body, &q)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"ok":false,"diagnostic":"unable to unmarshal probe"}`))
			return
		}

		rip := netip.MustParseAddr(q.Addr)
		vip := rip // fake the vip - NAT will take care of filling in the right address

		var rep reply

		rep.OK, rep.Diagnostic = monitor.Probe(vip, rip, q.Check)

		js, err := json.Marshal(&rep)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"ok":false,"diagnostic":"unable to marshal response"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(js)
	})

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

func unix(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socket)
			},
		},
	}
}

func (s *Stats) xvs(x xvs.Stats, y Stats) Stats {
	s.Octets = x.Octets
	s.Packets = x.Packets
	s.Flows = x.Flows
	s.Current = x.Current
	s.time = time.Now()

	if y.time.Unix() != 0 {
		diff := uint64(s.time.Sub(y.time) / time.Millisecond)

		if diff != 0 {
			s.OctetsPerSecond = (1000 * (s.Octets - y.Octets)) / diff
			s.PacketsPerSecond = (1000 * (s.Packets - y.Packets)) / diff
			s.FlowsPerSecond = (1000 * (s.Flows - y.Flows)) / diff
		}
	}

	return *s
}

func (s *Summary) xvs(x xvs.Info, y Summary) Summary {
	s.Latency = x.Latency
	s.Dropped = x.Dropped
	s.Blocked = x.Blocked

	s.Octets = x.Octets
	s.Packets = x.Packets
	s.Flows = x.Flows
	s.time = time.Now()

	if y.time.Unix() != 0 {
		diff := uint64(s.time.Sub(y.time) / time.Millisecond)

		if diff != 0 {
			s.DroppedPerSecond = (1000 * (s.Dropped - y.Dropped)) / diff
			s.BlockedPerSecond = (1000 * (s.Blocked - y.Blocked)) / diff
			s.NotQueuedPerSecond = (1000 * (s.NotQueued - y.NotQueued)) / diff

			s.OctetsPerSecond = (1000 * (s.Octets - y.Octets)) / diff
			s.PacketsPerSecond = (1000 * (s.Packets - y.Packets)) / diff
			s.FlowsPerSecond = (1000 * (s.Flows - y.Flows)) / diff
		}
	}

	return *s
}

type VIP = netip.Addr
type VIPStats struct {
	VIP   VIP   `json:"vip"`
	Up    bool  `json:"up"`
	Stats Stats `json:"stats"`
}

func vipStatus(in map[VIP][]Serv, rib []netip.Addr) (out []VIPStats) {

	foo := map[VIP]bool{}

	for _, r := range rib {
		foo[r] = true
	}

	for vip, list := range in {
		var stats Stats
		for _, s := range list {
			stats.add(s.Stats)
		}

		out = append(out, VIPStats{VIP: vip, Stats: stats, Up: foo[vip]})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].VIP.Compare(out[j].VIP) < 0
	})

	return
}

func serviceStatus(config *Config, client *Client, director *vc5ng.Director, _stats map[Key]Stats, _state map[Tuple]State) (map[VIP][]Serv, map[Key]Stats, map[Tuple]State, uint64) {

	var current uint64

	state := map[Tuple]State{}
	stats := map[Key]Stats{}
	status := map[VIP][]Serv{}

	for _, svc := range director.Status() {

		xs := xvs.Service{Address: svc.Address, Port: svc.Port, Protocol: xvs.Protocol(svc.Protocol)}
		xse, _ := client.Service(xs)

		t := Tuple{Addr: svc.Address, Port: svc.Port, Protocol: svc.Protocol}
		cnf, _ := config.Services[t]

		available := svc.Available()

		up := available >= svc.Required

		if s, exists := _state[t]; !exists || s.up != up {
			state[t] = State{up: up, time: time.Now()}
		} else {
			state[t] = s
		}

		serv := Serv{
			Name:        cnf.Name,
			Description: cnf.Description,
			Address:     svc.Address,
			Port:        svc.Port,
			Protocol:    protocol(svc.Protocol),
			Required:    svc.Required,
			Available:   available,
			Up:          up,
			For:         uint64(time.Now().Sub(state[t].time) / time.Second),
		}

		key := Key{VIP: svc.Address, Port: svc.Port, Protocol: svc.Protocol}
		stats[key] = serv.Stats.xvs(xse.Stats, _stats[key])

		xvs := map[netip.Addr]xvs.Stats{}
		mac := map[netip.Addr]string{}

		xd, _ := client.Destinations(xs)
		for _, d := range xd {
			xvs[d.Destination.Address] = d.Stats
			mac[d.Destination.Address] = d.MAC.String()
			current += d.Stats.Current
		}

		for _, dst := range svc.Destinations {
			s, _ := xvs[dst.Address]

			status := dst.Status

			dest := Dest{
				Address:    dst.Address,
				Port:       dst.Port,
				Disabled:   dst.Disabled,
				Up:         status.OK,
				For:        uint64(time.Now().Sub(status.When) / time.Second),
				Took:       uint64(status.Took / time.Millisecond),
				Diagnostic: status.Diagnostic,
				Weight:     dst.Weight,
				MAC:        mac[dst.Address],
			}

			key := Key{VIP: svc.Address, RIP: dst.Address, Port: svc.Port, Protocol: svc.Protocol}
			stats[key] = dest.Stats.xvs(s, _stats[key])

			serv.Destinations = append(serv.Destinations, dest)
		}

		sort.SliceStable(serv.Destinations, func(i, j int) bool {
			return serv.Destinations[i].Address.Compare(serv.Destinations[j].Address) < 0
		})

		status[svc.Address] = append(status[svc.Address], serv)
	}

	return status, stats, state, current
}
