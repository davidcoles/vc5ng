package balancer

import (
	"net/netip"

	"github.com/davidcoles/vc5ng"
	"github.com/davidcoles/xvs"
)

type Client = xvs.Client

type Balancer struct {
	Client  *Client
	ProbeFn func(addr netip.Addr, check vc5ng.Check) (bool, string)
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

	if b.ProbeFn == nil {
		return false, "No probe function defined"
	}

	nat, ok := b.Client.NATAddress(vip, rip)

	if !ok {
		return false, "No NAT destination defined for " + vip.String() + "/" + rip.String()
	}

	return b.ProbeFn(nat, check)
}

func evaluate(services []vc5ng.Service) bool {
	for _, s := range services {
		for d, _ := range s.Destinations {
			if s.Port != d.Port {
				return false
			}
		}
	}
	return true
}

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

		for ipp, d := range s.Destinations {
			if ipp.Port == s.Port {
				dsts = append(dsts, xvs.Destination{
					Address: ipp.Addr,
					Weight:  d.HealthyWeight(),
				})
			}
		}

		b.Client.SetService(service, dsts)
	}
}
