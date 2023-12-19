package vc5ng

import (
	"errors"
	//"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/davidcoles/vc5ng/config"
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

	Sticky       bool
	Required     uint8
	Available    uint8
	Destinations map[IPPort]Destination
}

type Destination struct {
	Disabled    bool   `json:"disabled"`
	Initialised bool   `json:"initialised"`
	Healthy     bool   `json:"healthy"`
	Weight      uint8  `json:"weight"`
	Diagnostic  string `json:"diagnostic"`
	Checks      []mon.Check
}

func (d *Destination) HealthyWeight() uint8 {
	if !d.Disabled && d.Healthy && d.Weight > 0 {
		return 1
	}
	return 0
}

func DestinationKey(addr netip.Addr, port uint16) IPPort {
	return IPPort{Addr: addr, Port: port}
}

type Tuple = config.IPPortProtocol
type IPPort = config.IPPort
type Check = mon.Check
type Target = map[Tuple]Service

func ServiceKey(addr netip.Addr, port uint16, protocol uint8) Tuple {
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

func (i Service) Compare(j Service) (r int) {
	if r = i.Address.Compare(j.Address); r != 0 {
		return r
	}

	if i.Port < j.Port {
		return -1
	}

	if i.Port > j.Port {
		return 1
	}

	if i.Protocol < j.Protocol {
		return -1
	}

	if i.Protocol > j.Protocol {
		return 1
	}

	return 0
}

type Balancer interface {
	Synchronise(map[Tuple]Service)
}

type Director struct {
	C        chan bool
	Balancer Balancer
	prober   Prober
	mutex    sync.Mutex
	//cfg      map[Tuple]config.Service
	cfg2 map[Tuple]Service
	mon  *mon.Mon
	die  chan bool
}

type NilBalancer struct{}

func (b *NilBalancer) Synchronise(map[Tuple]Service) {}

func (d *Director) balancer() Balancer {
	b := d.Balancer

	if b == nil {
		return &NilBalancer{}
	}

	return b
}

func (d *Director) Start(ip netip.Addr, cfg map[Tuple]Service) (err error) {

	d.C = make(chan bool, 1)

	prober, _ := d.balancer().(Prober)

	d.mon, err = mon.New(ip, nil, prober)

	if err != nil {
		return err
	}

	/*
		err = d.Configure(cfg)

		if err != nil {
			d.mon.Update(nil)
			return err
		}
	*/

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

//func (d *Director) Configure(cfg map[Tuple]config.Service) error {
//	return d.Configure2(Parse(cfg))
//}

/*
func (d *Director) _Configure(cfg map[Tuple]config.Service) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	vips := map[netip.Addr]bool{}
	svcs := map[mon.Service]bool{}

	for s, _ := range d.cfg {
		vips[s.Addr] = true
		svcs[mon.Service{Address: s.Addr, Port: s.Port, Protocol: s.Protocol}] = true
	}

	services := map[mon.Instance]mon.Foo{}

	for ipp, svc := range cfg {
		if ipp.Port == 0 {
			return errors.New("Service port cannot be 0")
		}

		if ipp.Protocol != TCP && ipp.Protocol != UDP {
			return errors.New("Only TCP and UDP protocols supported")
		}

		for ip, _ := range svc.Destinations {
			if ip.Port == 0 {
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

		for ip, r := range svc.Destinations {
			d := mon.Destination{Address: ip.Addr, Port: ip.Port}
			i := mon.Instance{Service: s, Destination: d}
			services[i] = mon.Foo{Init: init, Checks: r.Checks}
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
*/

func (d *Director) Configure(cfg2 map[Tuple]Service) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	vips := map[netip.Addr]bool{}
	svcs := map[mon.Service]bool{}

	for s, _ := range cfg2 {
		vips[s.Addr] = true
		svcs[mon.Service{Address: s.Addr, Port: s.Port, Protocol: s.Protocol}] = true
	}

	services := map[mon.Instance]mon.Target{}

	for ipp, svc := range cfg2 {
		if ipp.Port == 0 {
			return errors.New("Service port cannot be 0")
		}

		if ipp.Protocol != TCP && ipp.Protocol != UDP {
			return errors.New("Only TCP and UDP protocols supported")
		}

		for ip, _ := range svc.Destinations {
			if ip.Port == 0 {
				return errors.New("Destination port cannot be 0")
			}
		}
	}

	for ipp, svc := range cfg2 {

		s := mon.Service{Address: ipp.Addr, Port: ipp.Port, Protocol: ipp.Protocol}

		// When:
		// 1) adding a new vip, all checks should start as down(false) to prevent routing flaps
		// 2) adding a new service to an existing vip, start up(true) to prevent vip being withdrawn
		// 3) adding a new real to an existing service, start as down(false) state to prevent rehash

		init := vips[ipp.Addr] && !svcs[s]
		// 1: false && ?????? => false
		// 2: true  && !false => true
		// 3: true  && !true  => false

		for ip, r := range svc.Destinations {
			d := mon.Destination{Address: ip.Addr, Port: ip.Port}
			i := mon.Instance{Service: s, Destination: d}
			services[i] = mon.Target{Init: init, Checks: r.Checks}
		}
	}

	d.cfg2 = cfg2

	// balancer update should return a bool/error value to inidcate if the config was acceptable
	// only do d.cfg = cfg if it was
	d.balancer().Synchronise(d.services())
	d.mon.Update(services)
	d.inform()

	return nil
}

func (d *Director) RIBv4() (rib [][4]byte) {
	for _, r := range d.RIB() {
		if r.Is4() {
			rib = append(rib, r.As4())
		}
	}
	return
}

func (d *Director) RIBv6() (rib [][16]byte) {
	for _, r := range d.RIB() {
		if r.Is6() {
			rib = append(rib, r.As16())
		}
	}
	return
}

func (d *Director) RIB() (rib []netip.Addr) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	vips := map[netip.Addr]bool{}

	for _, svc := range d.services() {
		vip := svc.Address

		if svc.Available >= svc.Required {
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

		c.Destinations = map[IPPort]Destination{}

		for k, v := range s.Destinations {
			c.Destinations[k] = v
		}

		out = append(out, c)
	}

	return out
}

func Parse(cfg map[Tuple]config.Service) map[Tuple]Service {
	services := map[Tuple]Service{}

	for ipp, svc := range cfg {

		service := Service{
			Address:      ipp.Addr,
			Port:         ipp.Port,
			Protocol:     ipp.Protocol,
			Destinations: map[IPPort]Destination{},
			Required:     svc.Need,
			Sticky:       svc.Sticky,
		}

		for ap, dst := range svc.Destinations {

			destination := Destination{
				Weight:   dst.Weight,
				Disabled: dst.Disabled,
				Checks:   append([]mon.Check{}, dst.Checks...),
			}

			service.Destinations[ap] = destination
		}

		services[ipp] = service
	}

	return services
}

func (d *Director) services() map[Tuple]Service {
	services := map[Tuple]Service{}

	//for ipp, svc := range d.cfg {
	for ipp, svc := range d.cfg2 {

		service := Service{
			Address:      ipp.Addr,
			Port:         ipp.Port,
			Protocol:     ipp.Protocol,
			Destinations: map[IPPort]Destination{},
			//Required:     svc.Need,
			Required: svc.Required,
			Sticky:   svc.Sticky,
		}

		sv := mon.Service{Address: ipp.Addr, Port: ipp.Port, Protocol: ipp.Protocol}

		var available uint8

		for ap, dst := range svc.Destinations {

			ds := mon.Destination{Address: ap.Addr, Port: ap.Port}

			status, _ := d.mon.Status(sv, ds)

			destination := Destination{
				Weight:      dst.Weight,
				Disabled:    dst.Disabled,
				Healthy:     status.OK,
				Initialised: status.Initialised,
				Diagnostic:  status.Diagnostic,
			}

			if destination.HealthyWeight() > 0 {
				available++
			}

			service.Destinations[ap] = destination
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

	sort.SliceStable(services, func(i, j int) bool {
		return services[i].Compare(services[j]) < 0
	})

	return
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
			//fmt.Println("Something changed:")
			d.update()
		case <-d.die:
			d.Configure(nil)
			d.mon.Update(nil)
			d.inform()
			return
		}
	}
}
