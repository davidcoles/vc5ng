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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/davidcoles/vc5ng"
	"github.com/davidcoles/vc5ng/bgp"
	"github.com/davidcoles/vc5ng/mon"
	"github.com/davidcoles/xvs"
	// "github.com/davidcoles/cue"  pov pan
)

// TODO:

//go:embed static/*
var STATIC embed.FS

type Client = xvs.Client

func main() {
	F := "vc5"

	var mutex sync.Mutex

	start := time.Now()
	sock := flag.String("s", "", "socket")
	native := flag.Bool("n", false, "Native mode XDP")
	redirect := flag.Bool("r", false, "Redirect mode")
	webserver := flag.String("w", ":80", "Redirect mode")

	flag.Parse()

	args := flag.Args()

	if *sock != "" {
		// we're going to be the server running in the network namespace ...
		signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
		netns(*sock, netip.MustParseAddr(args[0]))
		return
	}

	logs := &logger{}

	socket, err := ioutil.TempFile("/tmp", "vc5ns")

	if err != nil {
		logs.EMERG(F, "socket", err)
		log.Fatal(err)
	}

	defer os.Remove(socket.Name())

	file := args[0]
	addr := netip.MustParseAddr(args[1])
	nics := args[2:]

	if !addr.Is4() {
		logs.EMERG(F, "Address is not IPv4:", addr)
		log.Fatal("Address is not IPv4: ", addr)
	}

	config, err := Load(file)

	if err != nil {
		logs.EMERG(F, "Couldn't load config file:", config, err)
		log.Fatal("Couldn't load config file:", config, err)
	}

	if config.Webserver != "" {
		*webserver = config.Webserver
	}

	client := &Client{
		Interfaces: nics,
		Address:    addr,
		Redirect:   *redirect,
		Native:     *native,
		VLANs:      config.vlans(),
		NAT:        true,
		Logger:     logs.sub("xvs"),
		Share:      config.Multicast != "",
	}

	err = client.Start()

	if err != nil {
		logs.EMERG(F, "Couldn't start client:", err)
		log.Fatal(err)
	}

	if config.Multicast != "" {
		go multicast_send(client, config.Multicast)
		go multicast_recv(client, config.Multicast)
	}

	pool := bgp.NewPool(addr.As4(), config.BGP, nil, logs.sub("bgp"))

	if pool == nil {
		log.Fatal("BGP pool fail")
	}

	go spawn(logs, client.Namespace(), os.Args[0], "-s", socket.Name(), client.NamespaceAddress())

	af_unix := unix(socket.Name())

	director := &vc5ng.Director{
		Logger: logs.sub("director"),
		Balancer: &Balancer{
			Client: client,
			ProbeFunc: func(vip, rip, nat netip.Addr, check mon.Check) (bool, string) {
				return probe(af_unix, vip, rip, nat, check, logs)
			},
		},
	}

	err = director.Start(config.parse())

	if err != nil {
		logs.EMERG(F, "Couldn't start director:", err)
		log.Fatal(err)
	}

	done := make(chan bool)

	vip := map[netip.Addr]State{}

	var rib []netip.Addr
	var summary Summary

	services, old, _ := serviceStatus(config, client, director, nil)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			mutex.Lock()
			summary.xvs(client.Info(), summary)
			summary.Uptime = uint64(time.Now().Sub(start) / time.Second)
			services, old, summary.Current = serviceStatus(config, client, director, old)
			mutex.Unlock()
			select {
			case <-ticker.C:
			case <-done:
				return
			}
		}
	}()

	go func() { // advertise VIPs via BGP
		timer := time.NewTimer(config.Learn * time.Second)
		ticker := time.NewTicker(5 * time.Second)
		services := director.Status()

		defer func() {
			ticker.Stop()
			timer.Stop()
			pool.RIB(nil)
			time.Sleep(2 * time.Second)
			pool.Close()
		}()

		var initialised bool
		for {
			select {
			case <-ticker.C: // check for matured VIPs
			case <-director.C: // a backend has changed state
				services = director.Status()
			case <-done: // shuting down
				return
			case <-timer.C:
				logs.NOTICE(F, KV{"event": "Learn timer expired"})
				initialised = true
			}

			mutex.Lock()
			vip = vipState(services, vip, logs)
			rib = adjRIBOut(vip, initialised)
			mutex.Unlock()

			pool.RIB(rib)
		}
	}()

	fmt.Println("******************** RUNNING ********************")

	static := http.FS(STATIC)
	//var fs http.FileSystem

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "static/" + r.URL.Path
		http.FileServer(static).ServeHTTP(w, r)
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {

		start, _ := strconv.ParseUint(r.URL.Path[5:], 10, 64)

		w.Header().Set("Content-Type", "application/json")

		logs := logs.get(index(start))

		js, _ := json.MarshalIndent(&logs, " ", " ")

		w.Write(js)
		w.Write([]byte("\n"))
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
		log.Fatal(http.ListenAndServe(*webserver, nil))
	}()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGQUIT:
			logs.ALERT(F, "SIGQUIT received - shutting down")
			fmt.Println("CLOSING")
			close(done) // shut down BGP, etc
			time.Sleep(4 * time.Second)
			fmt.Println("DONE")
			return
		case syscall.SIGINT:
			logs.NOTICE(F, "Reload signal received")
			conf, err := Load(file)
			if err == nil {
				mutex.Lock()
				config = conf
				client.UpdateVLANs(config.vlans())
				director.Configure(config.parse())
				pool.Configure(config.BGP)
				mutex.Unlock()
			} else {
				logs.ALERT(F, "Couldn't load config file:", file, err)
			}
		}
	}
}

type query struct {
	Address string    `json:"address"`
	Check   mon.Check `json:"check"`
}

type reply struct {
	OK         bool   `json:"ok"`
	Diagnostic string `json:"diagnostic"`
}

func probe(client *http.Client, vip, rip, addr netip.Addr, check mon.Check, l *logger) (bool, string) {

	q := query{Address: addr.String(), Check: check}

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

	type KV = map[string]any
	//expect := fmt.Sprintf("%v", check.Expect)
	//method := ""

	kv := KV{
		"event": "healthcheck",
		"nat":   addr.String(),
		"vip":   vip.String(),
		"rip":   rip.String(),
		"port":  check.Port,
		"type":  check.Type,
		//"method":     method,
		//"host":       check.Host,
		//"path":       check.Path,
		//"expect":     expect,
		"status":     updown(r.OK),
		"diagnostic": r.Diagnostic,
	}

	switch check.Type {
	case "dns":
		if check.Method {
			kv["method"] = "tcp"
		} else {
			kv["method"] = "udp"
		}
	case "http":
		fallthrough
	case "https":
		if check.Method {
			kv["method"] = "GET"
		} else {
			kv["method"] = "HEAD"
		}

		if check.Host != "" {
			kv["host"] = check.Host
		}

		if check.Path != "" {
			kv["path"] = check.Path
		}

		if len(check.Expect) > 0 {
			kv["expect"] = fmt.Sprintf("%v", check.Expect)
		}
	}

	//kv["check"] = check

	if l != nil {
		l.DEBUG("PROBER", kv)
	}

	return r.OK, r.Diagnostic
}

// spawn a server (specified by args) which runs in the network namespace - if it dies then restart it
func spawn(logs *logger, netns string, args ...string) {
	F := "netns"
	for {
		logs.DEBUG(F, "Spawning daemon", args)

		cmd := exec.Command("ip", append([]string{"netns", "exec", netns}, args...)...)
		_, _ = cmd.StdinPipe()
		stderr, _ := cmd.StderrPipe()
		stdout, _ := cmd.StdoutPipe()

		reader := func(s string, fh io.ReadCloser) {
			scanner := bufio.NewScanner(fh)
			for scanner.Scan() {
				//fmt.Println("NETNS:", s, scanner.Text())
				logs.WARNING(F, s, scanner.Text())
			}
		}

		go reader("stderr", stderr)

		if err := cmd.Start(); err != nil {
			//log.Println("Daemon", err)
			logs.ERR(F, "Daemon", err)
		} else {
			reader("stdout", stdout)

			if err := cmd.Wait(); err != nil {
				//log.Println("Daemon", err)
				logs.ERR(F, "Daemon", err)
			}
		}

		logs.ERR(F, "Daemon exited")

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

	//monitor, err := mon.New(addr, nil, nil, &logger{})
	monitor, err := mon.New(addr, nil, nil, nil)

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

		rip := netip.MustParseAddr(q.Address)
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
	s.NotQueued = x.NotQueued

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

	up := map[VIP]bool{}

	for _, r := range rib {
		up[r] = true
	}

	for vip, list := range in {
		var stats Stats
		for _, s := range list {
			stats.add(s.Stats)
		}

		out = append(out, VIPStats{VIP: vip, Stats: stats, Up: up[vip]})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].VIP.Compare(out[j].VIP) < 0
	})

	return
}

func serviceStatus(config *Config, client *Client, director *vc5ng.Director, _stats map[Key]Stats) (map[VIP][]Serv, map[Key]Stats, uint64) {

	var current uint64

	stats := map[Key]Stats{}
	status := map[VIP][]Serv{}

	for _, svc := range director.Status() {

		xs := xvs.Service{Address: svc.Address, Port: svc.Port, Protocol: xvs.Protocol(svc.Protocol)}
		xse, _ := client.Service(xs)

		t := Tuple{Addr: svc.Address, Port: svc.Port, Protocol: svc.Protocol}
		cnf, _ := config.Services[t]

		available := svc.Available()

		serv := Serv{
			Name:        cnf.Name,
			Description: cnf.Description,
			Address:     svc.Address,
			Port:        svc.Port,
			Protocol:    protocol(svc.Protocol),
			Required:    svc.Required,
			Available:   available,
			Up:          svc.Up,
			For:         uint64(time.Now().Sub(svc.When) / time.Second),
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

	return status, stats, current
}

func updown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

const maxDatagramSize = 1500

func multicast_send(client *Client, address string) {

	addr, err := net.ResolveUDPAddr("udp", address)

	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUDP("udp", nil, addr)

	if err != nil {
		log.Fatal(err)
	}

	conn.SetWriteBuffer(maxDatagramSize * 100)

	ticker := time.NewTicker(time.Millisecond * 10)

	var buff [maxDatagramSize]byte

	for {
		select {
		case <-ticker.C:
			n := 0

		read_flow:
			f := client.ReadFlow()
			if len(f) > 0 {
				buff[n] = uint8(len(f))

				copy(buff[n+1:], f[:])
				n += 1 + len(f)
				if n < maxDatagramSize-100 {
					goto read_flow
				}
			}

			if n > 0 {
				conn.Write(buff[:n])
			}
		}
	}
}

func multicast_recv(client *Client, address string) {
	udp, err := net.ResolveUDPAddr("udp", address)

	if err != nil {
		log.Fatal(err)
	}

	s := []string{`|`, `/`, `-`, `\`}
	var x int

	conn, err := net.ListenMulticastUDP("udp", nil, udp)

	conn.SetReadBuffer(maxDatagramSize * 1000)

	buff := make([]byte, maxDatagramSize)

	for {
		nread, _, err := conn.ReadFromUDP(buff)
		fmt.Print(s[x%4] + "\b")
		x++
		if err == nil {
			for n := 0; n+1 < nread; {
				l := int(buff[n])
				o := n + 1
				n = o + l
				if l > 0 && n <= nread {
					client.WriteFlow(buff[o:n])
				}
			}
		}
	}
}

func adjRIBOut(vip map[netip.Addr]State, initialised bool) (r []netip.Addr) {
	for v, s := range vip {
		if initialised && s.up && time.Now().Sub(s.time) > time.Second*5 {
			r = append(r, v)
		}
	}
	return
}

func vipState(services []vc5ng.Service, old map[netip.Addr]State, logs *logger) map[netip.Addr]State {
	F := "vips"

	rib := map[netip.Addr]bool{}
	new := map[netip.Addr]State{}

	for _, v := range vc5ng.HealthyVIPs(services) {
		rib[v] = true
	}

	for _, v := range vc5ng.AllVIPs(services) {

		if o, ok := old[v]; ok {
			up, _ := rib[v]

			if o.up != up {
				new[v] = State{up: up, time: time.Now()}
				logs.NOTICE(F, KV{"vip": v, "state": updown(up), "event": "vip"})
			} else {
				new[v] = o
			}

		} else {
			logs.NOTICE(F, KV{"vip": v, "state": updown(rib[v]), "event": "vip"})
			new[v] = State{up: rib[v], time: time.Now()}
		}
	}

	return new
}
