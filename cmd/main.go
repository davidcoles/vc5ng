package main

import (
	"bufio"
	"bytes"
	"context"
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
	"sync"
	"syscall"
	"time"

	"github.com/davidcoles/xvs"

	"github.com/davidcoles/vc5ng"
	"github.com/davidcoles/vc5ng/balancer"
	"github.com/davidcoles/vc5ng/bgp"
	"github.com/davidcoles/vc5ng/mon"
)

var mutex sync.Mutex
var pool *bgp.Pool
var client *xvs.Client
var config *Config
var director *vc5ng.Director

func main() {

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

	config, err = Load(file)

	if err != nil {
		log.Fatal(err)
	}

	client = &xvs.Client{
		Interfaces: nics,
		Address:    addr,
		Redirect:   *redirect,
		Native:     *native,
		VLANs:      config.VLANs(),
		NAT:        true,
		//Namespace: "vc5",
	}

	err = client.Start()

	if err != nil {
		log.Fatal(err)
	}

	go spawn(client.Namespace(), os.Args[0], "-s", socket.Name(), client.NamespaceAddress())

	pool = bgp.NewPool(addr.As4(), config.BGP, nil)

	if pool == nil {
		log.Fatal("BGP pool fail")
	}

	af_unix := unix(socket.Name())

	director = &vc5ng.Director{
		Balancer: &balancer.Balancer{
			Client: client,
			ProbeFn: func(addr netip.Addr, check mon.Check) (bool, string) {
				return probe(af_unix, addr, check)
			},
		},
	}

	director.Start(addr, Parse(config.Services))

	done := make(chan bool)
	go signals(file, done)

	rib := director.RIBv4()
	xyz := map[string][]Serv{}

	go func() {
		old := map[Key]Stats{}
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			mutex.Lock()
			xyz, old = serviceStatus(old)
			mutex.Unlock()
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()

	go func() { // advertise VIPs via BGP
		timer := time.NewTimer(30 * time.Second)
		var init bool
		for {
			select {
			case _, ok := <-director.C:
				if !ok {
					return
				}
			case <-timer.C:
				fmt.Println("STARTS")
				init = true
			}
			if init {
				mutex.Lock()
				rib = director.RIBv4()
				fmt.Println("RIB:", rib)
				pool.RIB(rib)
				mutex.Unlock()
			}
		}
	}()

	fmt.Println("******************** RUNNING ********************")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(client.Info())
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello, World!\n"))
	})

	http.HandleFunc("/vc5ng", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(client.Info())
		w.Header().Set("Content-Type", "application/json")
		status := director.Status()
		js, err := json.MarshalIndent(&status, " ", " ")
		fmt.Println(err)
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/xvs", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(client.Info())
		w.Header().Set("Content-Type", "application/json")
		js, _ := json.MarshalIndent(xvsStatus(client), " ", " ")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var ribs []netip.Addr

		mutex.Lock()

		for _, r := range rib {
			ribs = append(ribs, netip.AddrFrom4(r))
		}

		type status struct {
			Info     xvs.Info
			Services map[string][]Serv
			BGP      map[string]bgp.Status
			RIB      []netip.Addr
		}

		js, _ := json.MarshalIndent(&status{
			Info:     client.Info(),
			Services: xyz,
			BGP:      pool.Status(),
			RIB:      ribs,
		}, " ", " ")

		mutex.Unlock()

		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/prefixes", func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		p := client.Prefixes()
		fmt.Println(time.Now().Sub(t))
		for k, v := range p {
			if v != 0 {
				fmt.Println("****", k, v)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		js, _ := json.Marshal(&p)
		w.Write(js)
		w.Write([]byte("\n"))
	})

	go func() {
		log.Fatal(http.ListenAndServe(":80", nil))
	}()

	<-done
}

func xvsStatus(client *xvs.Client) *[]interface{} {

	type status struct {
		Service      xvs.ServiceExtended
		Destinations []xvs.DestinationExtended
	}

	var ret []interface{}

	svcs, _ := client.Services()

	for _, se := range svcs {
		dsts, _ := client.Destinations(se.Service)
		ret = append(ret, status{Service: se, Destinations: dsts})
	}

	return &ret
}

func signals(file string, done chan bool) {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGQUIT:
			director.Stop()
			close(done)
			fmt.Println("CLOSING")
		case syscall.SIGINT:
			conf, err := Load(file)
			if err == nil {
				mutex.Lock()
				config = conf
				client.UpdateVLANs(config.VLANs())
				director.Configure(Parse(config.Services))
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
		// if stding is closed (parent dies) then exit
		reader := bufio.NewReader(os.Stdin)
		_, _, err := reader.ReadRune()

		if err != nil {
			os.Remove(socket)
			log.Fatal(err)
		}
	}()

	monitor, err := mon.New(addr, nil, nil)

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
		vip := rip // fake the vip - NAT will take care of filling the right address in

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

type Serv struct {
	Name         string
	Description  string
	Port         uint16
	Protocol     uint8
	Required     uint8
	Available    uint8
	Stats        Stats
	Destinations []Dest
}

type Dest struct {
	Address    string
	Port       uint16
	Stats      Stats
	Weight     uint8
	Disabled   bool
	Up         bool
	When       uint64
	Last       uint64
	Duration   uint64
	Diagnostic string
	MAC        string
}

type tuple = IPPortProtocol

type Key struct {
	VIP      netip.Addr
	RIP      netip.Addr
	Port     uint16
	Protocol uint8
}

type Stats struct {
	Octets           uint64
	Packets          uint64
	Flows            uint64
	Current          uint64
	OctetsPerSecond  uint64
	PacketsPerSecond uint64
	FlowsPerSecond   uint64
	time             time.Time
}

func (s *Stats) xvs(x xvs.Stats, y Stats) Stats {
	s.Octets = x.Octets
	s.Packets = x.Packets
	s.Flows = x.Flows
	//s.Current = x.Current
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

func serviceStatus(old map[Key]Stats) (map[string][]Serv, map[Key]Stats) {

	new := map[Key]Stats{}
	ret := map[string][]Serv{}

	services := director.Status()

	for _, svc := range services {

		vip := svc.Address.String()

		list, _ := ret[vip]

		xs := xvs.Service{Address: svc.Address, Port: svc.Port, Protocol: xvs.Protocol(svc.Protocol)}
		xse, _ := client.Service(xs)

		cnf, _ := config.Services[tuple{Addr: svc.Address, Port: svc.Port, Protocol: svc.Protocol}]

		serv := Serv{
			Name:        cnf.Name,
			Description: cnf.Description,
			Port:        svc.Port,
			Protocol:    svc.Protocol,
			Required:    svc.Required,
			Available:   svc.Available,
		}

		key := Key{VIP: svc.Address, Port: svc.Port, Protocol: svc.Protocol}
		new[key] = serv.Stats.xvs(xse.Stats, old[key])

		stats := map[netip.Addr]xvs.Stats{}
		mac := map[netip.Addr]string{}

		xd, _ := client.Destinations(xs)
		for _, d := range xd {
			stats[d.Destination.Address] = d.Stats
			mac[d.Destination.Address] = d.MAC.String()
		}

		for addr, dst := range svc.Destinations {
			s, _ := stats[addr.Addr]

			dest := Dest{
				Address:    addr.Addr.String(),
				Port:       addr.Port,
				Disabled:   dst.Disabled,
				Up:         dst.Healthy,
				Weight:     dst.Weight,
				Diagnostic: dst.Diagnostic,
				MAC:        mac[addr.Addr],
			}

			key := Key{VIP: svc.Address, RIP: addr.Addr, Port: svc.Port, Protocol: svc.Protocol}
			new[key] = dest.Stats.xvs(s, old[key])

			serv.Destinations = append(serv.Destinations, dest)
		}

		ret[vip] = append(list, serv)
	}

	return ret, new
}
