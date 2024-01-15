package balancer

import (
	"errors"
	"net/netip"

	"github.com/davidcoles/vc5ng"
	"github.com/davidcoles/xvs"
)

type Client = xvs.Client

type tuple struct {
	addr netip.Addr
	port uint16
	prot uint8
}

type Balancer struct {
	Client    *Client
	ProbeFunc func(addr netip.Addr, check vc5ng.Check) (bool, string)
}

func (b *Balancer) Available(s vc5ng.Service) (available uint16) {

	service := xvs.Service{Address: s.Address, Port: s.Port, Protocol: xvs.Protocol(s.Protocol)}
	dsts, _ := b.Client.Destinations(service)

	for _, d := range dsts {
		if d.Destination.Weight > 0 {
			available++
		}
	}

	return
}

func (b *Balancer) Probe(vip netip.Addr, rip netip.Addr, check vc5ng.Check) (bool, string) {

	f := b.ProbeFunc

	if f == nil {
		return false, "No probe function defined"
	}

	nat, ok := b.Client.NATAddress(vip, rip)

	if !ok {
		return false, "No NAT destination defined for " + vip.String() + "/" + rip.String()
	}

	return f(nat, check)
}

func (b *Balancer) Configure(services []vc5ng.Service) error {

	target := map[tuple]vc5ng.Service{}

	for _, s := range services {
		target[tuple{addr: s.Address, port: s.Port, prot: s.Protocol}] = s

		for _, d := range s.Destinations {
			if s.Port != d.Port {
				return errors.New("Destination ports must match service ports for DSR")
			}
		}
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {
		key := tuple{addr: s.Service.Address, port: s.Service.Port, prot: s.Service.Protocol}
		if _, wanted := target[key]; !wanted {
			b.Client.RemoveService(s.Service)
		}
	}

	for _, s := range target {
		service := xvs.Service{Address: s.Address, Port: s.Port, Protocol: xvs.Protocol(s.Protocol), Sticky: s.Sticky}

		var dsts []xvs.Destination

		for _, d := range s.Destinations {
			if d.Port == s.Port {
				dsts = append(dsts, xvs.Destination{
					Address: d.Address,
					Weight:  d.HealthyWeight(),
				})
			}
		}

		b.Client.SetService(service, dsts)
	}

	return nil
}

/*
func (b *Balancer) Synchronise(target vc5ng.Target) {

	svcs, _ := b.Client.Services()
	for _, s := range svcs {
		key := vc5ng.ServiceKey(s.Service.Address, s.Service.Port, uint8(s.Service.Protocol))
		if _, wanted := target[key]; !wanted {
			b.Client.RemoveService(s.Service)
		}
	}

	for _, s := range target {
		service := xvs.Service{Address: s.Address, Port: s.Port, Protocol: xvs.Protocol(s.Protocol), Sticky: s.Sticky}

		var dsts []xvs.Destination

		for _, d := range s.Destinations {
			if d.Port == s.Port {
				dsts = append(dsts, xvs.Destination{
					Address: d.Address,
					Weight:  d.HealthyWeight(),
				})
			}
		}

		b.Client.SetService(service, dsts)
	}
}
*/
