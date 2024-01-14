package vc5ng

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/davidcoles/vc5ng/mon"
)

const (
	TCP = 0x06
	UDP = 0x11
)

type Prober = mon.Prober

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol uint8

	Sticky    bool
	Required  uint8
	Available uint8
	//_Destinations map[IPPort]Destination
	Destinations_ []Destination
}

type Destination struct {
	Address  netip.Addr `json:"address"`
	Port     uint16     `json:"port"`
	Disabled bool       `json:"disabled"`
	Weight   uint8      `json:"weight"`
	Status   mon.Status `json:"status"`
	Checks   []mon.Check
}

func (d *Destination) HealthyWeight() uint8 {
	if !d.Disabled && d.Status.OK && d.Weight > 0 {
		return 1
	}
	return 0
}

func DestinationKey(addr netip.Addr, port uint16) IPPort {
	return IPPort{Addr: addr, Port: port}
}

type Tuple = IPPortProtocol
type IPPortProtocol struct {
	Addr     netip.Addr
	Port     uint16
	Protocol uint8
}

type IPPort struct {
	Addr netip.Addr
	Port uint16
}

func (i IPPort) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%s:%d", i.Addr, i.Port)), nil
}

type Check = mon.Check
type Target = map[Tuple]Service

func SxxerviceKey(addr netip.Addr, port uint16, protocol uint8) Tuple {
	return Tuple{Addr: addr, Port: port, Protocol: protocol}
}

type protocol uint8

func (p protocol) MarshalText() ([]byte, error) {
	switch p {
	case TCP:
		return []byte("TCP"), nil
	case UDP:
		return []byte("UDP"), nil
	}
	return []byte("Unknown"), nil
}

func (s *Service) Healthy() bool {
	return s.Available >= s.Required
}

func (i Service) Less(j Service) bool {
	if r := i.Address.Compare(j.Address); r != 0 {
		return r < 0
	}

	if i.Port != j.Port {
		return i.Port < j.Port
	}

	if i.Protocol != j.Protocol {
		return i.Protocol < j.Protocol
	}

	return false
}

type Balancer interface {
	Synchronise(map[Tuple]Service)
	Available(Service) uint16
}

type Director struct {
	C        chan bool
	Balancer Balancer
	prober   Prober
	mutex    sync.Mutex
	cfg      map[Tuple]Service
	mon      *mon.Mon
	die      chan bool
}

type NilBalancer struct{}

func (b *NilBalancer) Synchronise(map[Tuple]Service) {}
func (b *NilBalancer) Available(Service) uint16      { return 0 }

func (d *Director) balancer() Balancer {
	b := d.Balancer

	if b == nil {
		return &NilBalancer{}
	}

	return b
}

// func (d *Director) Start(ip netip.Addr, cfg map[Tuple]Service) (err error) {
func (d *Director) Start(ip netip.Addr, cfg []Service) (err error) {

	d.C = make(chan bool, 1)

	prober, _ := d.balancer().(Prober)

	d.mon, err = mon.New(ip, nil, prober)

	if err != nil {
		return err
	}

	err = d.Configure(cfg)

	if err != nil {
		d.mon.Update(nil)
		return err
	}

	d.die = make(chan bool)

	go d.background()

	return nil
}

func (d *Director) Stop() {
	close(d.die)
}

// func (d *Director) Configure(cfg map[Tuple]Service) error {
func (d *Director) Configure(cf []Service) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	cfg := map[Tuple]Service{}

	//var cf []Service
	for _, s := range cf {
		t := Tuple{Addr: s.Address, Port: s.Port, Protocol: s.Protocol}
		cfg[t] = s
	}

	vips := map[netip.Addr]bool{}
	svcs := map[mon.Service]bool{}

	// scan previous config to see if vip/service existed ...
	for s, _ := range d.cfg {
		vips[s.Addr] = true
		svcs[mon.Service{Address: s.Addr, Port: s.Port, Protocol: s.Protocol}] = true
	}

	services := map[mon.Instance]mon.Target{}

	for ipp, svc := range cfg {
		if ipp.Port == 0 {
			return errors.New("Service port cannot be 0")
		}

		if ipp.Protocol != TCP && ipp.Protocol != UDP {
			return errors.New("Only TCP and UDP protocols supported")
		}

		//for ip, _ := range svc._Destinations {
		//	if ip.Port == 0 {
		//		return errors.New("Destination port cannot be 0")
		//	}
		//}

		for _, d := range svc.Destinations_ {
			if d.Port == 0 {
				return errors.New("Destination port cannot be 0")
			}
		}
	}

	for ipp, svc := range cfg {

		s := mon.Service{Address: ipp.Addr, Port: ipp.Port, Protocol: ipp.Protocol}

		// When:
		// 1) adding a new vip, all checks should start as down(false) to prevent routing flaps
		// 2) adding a new service to an existing vip, start up(true) to prevent vip being withdrawn
		// 3) adding a new real to an existing service, start as down(false) state to prevent rehash

		init := vips[ipp.Addr] && !svcs[s]
		// 1: false && ?????? => false
		// 2: true  && !false => true
		// 3: true  && !true  => false

		//for ip, r := range svc._Destinations {
		//	d := mon.Destination{Address: ip.Addr, Port: ip.Port}
		//	i := mon.Instance{Service: s, Destination: d}
		//	services[i] = mon.Target{Init: init, Checks: r.Checks}
		//}

		for _, d := range svc.Destinations_ {
			i := mon.Instance{Service: s, Destination: mon.Destination{Address: d.Address, Port: d.Port}}
			services[i] = mon.Target{Init: init, Checks: d.Checks}
		}
	}

	d.cfg = cfg

	// balancer update should return a bool/error value to inidcate if the config was acceptable
	// only do d.cfg = cfg if it was
	d.balancer().Synchronise(d.services())
	d.mon.Update(services)
	d.inform()

	return nil
}

func (d *Director) RIB() (rib []netip.Addr) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	vips := map[netip.Addr]bool{}

	for _, svc := range d.services() {
		vip := svc.Address

		av := d.Balancer.Available(svc)

		//fmt.Println(vip, svc.Available, svc.Required, av)
		if svc.Available >= svc.Required && av >= uint16(svc.Required) {
			if _, ok := vips[vip]; !ok {
				vips[vip] = true
			}
		} else {
			vips[vip] = false
		}
	}

	for ip, ok := range vips {
		if ok {
			rib = append(rib, ip)
		}
	}

	return rib
}

func clone(in []Service) (out []Service) {

	for _, s := range in {
		c := s

		//c._Destinations = map[IPPort]Destination{}
		//for k, v := range s._Destinations {
		//	c._Destinations[k] = v
		//}

		c.Destinations_ = nil
		for _, d := range s.Destinations_ {
			c.Destinations_ = append(c.Destinations_, d)
		}

		out = append(out, c)
	}

	return out
}

func (d *Director) services() map[Tuple]Service {
	services := map[Tuple]Service{}

	for ipp, svc := range d.cfg {

		service := Service{
			Address:  ipp.Addr,
			Port:     ipp.Port,
			Protocol: ipp.Protocol,
			//_Destinations: map[IPPort]Destination{},
			Required: svc.Required,
			Sticky:   svc.Sticky,
		}

		sv := mon.Service{Address: ipp.Addr, Port: ipp.Port, Protocol: ipp.Protocol}

		var available uint8

		/*
			for ap, dst := range svc.Destinations {

				ds := mon.Destination{Address: ap.Addr, Port: ap.Port}

				status, _ := d.mon.Status(sv, ds)

				destination := Destination{
					Weight:   dst.Weight,
					Disabled: dst.Disabled,
					Status:   status,
				}

				if destination.HealthyWeight() > 0 {
					available++
				}

				service.Destinations[ap] = destination
			}
		*/

		for _, destination := range svc.Destinations_ {

			ds := mon.Destination{Address: destination.Address, Port: destination.Port}

			status, _ := d.mon.Status(sv, ds)

			destination.Status = status

			if destination.HealthyWeight() > 0 {
				available++
			}

			service.Destinations_ = append(service.Destinations_, destination)

			//ap := IPPort{Addr: destination.Address, Port: destination.Port}
			//service._Destinations[ap] = destination
		}

		service.Available = available

		services[ipp] = service
	}

	return services
}

func (d *Director) Status() (services []Service) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	for _, s := range d.services() {
		services = append(services, s)
	}

	sort.SliceStable(services, func(i, j int) bool { return services[i].Less(services[j]) })

	return services
}

func (d *Director) update() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.balancer().Synchronise(d.services())
	d.inform()
}

func (d *Director) inform() {
	select {
	case d.C <- true:
	default:
	}
}

func (d *Director) background() {
	for {
		select {
		case <-d.mon.C:
			d.update()
		case <-d.die:
			d.Configure(nil)
			d.mon.Update(nil)
			d.inform()
			return
		}
	}
}
