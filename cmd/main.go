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
	"syscall"
	"time"

	"github.com/davidcoles/xvs"

	"github.com/davidcoles/vc5ng"
	"github.com/davidcoles/vc5ng/balancer"
	"github.com/davidcoles/vc5ng/bgp"
	//"github.com/davidcoles/vc5ng/config"
	"github.com/davidcoles/vc5ng/mon"
)

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

	//conf, err := config.Load(file)
	conf, err := Load(file)

	if err != nil {
		log.Fatal(err)
	}

	client := &xvs.Client{
		Interfaces: nics,
		Address:    addr,
		Redirect:   *redirect,
		Native:     *native,
		VLANs:      conf.VLANs(),
		NAT:        true,
		//Namespace: "vc5",
	}

	err = client.Start()

	if err != nil {
		log.Fatal(err)
	}

	go spawn(client.Namespace(), os.Args[0], "-s", socket.Name(), client.NamespaceAddress())

	pool := bgp.NewPool(addr.As4(), conf.BGP, nil)

	if pool == nil {
		log.Fatal("BGP pool fail")
	}

	af_unix := unix(socket.Name())

	director := &vc5ng.Director{
		Balancer: &balancer.Balancer{
			Client: client,
			ProbeFn: func(addr netip.Addr, check mon.Check) (bool, string) {
				return probe(af_unix, addr, check)
			},
		},
	}

	//director.Start(addr, vc5ng.Parse(conf.Services))
	director.Start(addr, Parse(conf.Services))
	defer func() {
		director.Stop()
		time.Sleep(time.Second)
	}()

	done := make(chan bool)
	go signals(director, client, file, done)

	go func() { // advertise VIPs via BGP
		for _ = range director.C {
			rib := director.RIBv4()
			fmt.Println("RIB:", rib)
			pool.RIB(rib)
		}
	}()

	fmt.Println("******************** RUNNING ********************")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(client.Info())
		w.Header().Set("Content-Type", "application/json")
		status := director.Status()
		js, _ := json.MarshalIndent(&status, " ", " ")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/xvs", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(client.Info())
		w.Header().Set("Content-Type", "application/json")
		status := status(client)
		js, _ := json.MarshalIndent(&status, " ", " ")
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
		js, _ := json.MarshalIndent(&p, " ", " ")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	go func() {
		log.Fatal(http.ListenAndServe(":80", nil))
	}()

	<-done
}

type Status struct {
	Service      xvs.ServiceExtended
	Destinations []xvs.DestinationExtended
}

func status(client *xvs.Client) (status []Status) {

	svcs, _ := client.Services()

	for _, se := range svcs {
		dsts, _ := client.Destinations(se.Service)
		status = append(status, Status{Service: se, Destinations: dsts})
	}

	return
}

func signals(director *vc5ng.Director, client *xvs.Client, file string, done chan bool) {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGQUIT:
			fmt.Println("CLOSING")
			close(done)
		case syscall.SIGINT:
			//conf, err := config.Load(file)
			conf, err := Load(file)
			if err == nil {
				client.UpdateVLANs(conf.VLANs())
				director.Configure(Parse(conf.Services))
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
