package balancer

import (
	//"fmt"
	"net/netip"

	"github.com/davidcoles/vc5ng"
	"github.com/davidcoles/xvs"
)

type Client = xvs.Client

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

type Balancer struct {
	Client  *Client
	ProbeFn func(addr netip.Addr, check vc5ng.Check) (bool, string)
}

func (b *Balancer) Probe(vip netip.Addr, rip netip.Addr, check vc5ng.Check) (bool, string) {
	nat, ok := b.Client.NATAddress(vip, rip)

	if !ok {
		return false, "No NAT destination defined for " + vip.String() + "/" + rip.String()
	}

	if b.ProbeFn == nil {
		return false, "No probe function defined"
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

				//fmt.Println("d.HealthyWeight:", d.HealthyWeight())
			}
		}

		b.Client.SetService(service, dsts)
	}
}

/*

func (b *Balancer) _Synchronise(target vc5ng.Target) {

	svcs, _ := b.Client.Services()
	for _, s := range svcs {
		key := vc5ng.ServiceKey(s.Service.Address, s.Service.Port, uint8(s.Service.Protocol))
		if _, wanted := target[key]; !wanted {
			b.Client.RemoveService(s.Service)
		}
	}

	for _, s := range target {
		service := xvs.Service{Address: s.Address, Port: s.Port, Protocol: xvs.Protocol(s.Protocol), Sticky: s.Sticky}
		if _, err := b.Client.Service(service); err != nil {
			b.Client.CreateService(service)
		} else {
			b.Client.UpdateService(service)
		}

		dsts, _ := b.Client.Destinations(service)
		b.destinations(s, service, dsts)
	}
}

func (b *Balancer) destinations(target vc5ng.Service, xs xvs.Service, extant []xvs.DestinationExtended) {

	for _, d := range extant {
		key := vc5ng.DestinationKey(d.Destination.Address, xs.Port)
		status, wanted := target.Destinations[key]
		if wanted {
			fmt.Println("=============", d.Destination.Address, status.HealthyWeight())
			b.Client.UpdateDestination(xs, xvs.Destination{Address: d.Destination.Address, Weight: status.HealthyWeight()})
		} else {
			b.Client.RemoveDestination(xs, d.Destination) // exists in XVS, but not in target config - delete
		}
		delete(target.Destinations, key)
	}

	for d, status := range target.Destinations {
		// was not handled so does not exist in XVS - create
		if d.Port == xs.Port {
			//fmt.Println("--------", d.Addr, status.HealthyWeight())
			b.Client.CreateDestination(xs, xvs.Destination{Address: d.Addr, Weight: status.HealthyWeight()})
		} else {
			log.Println("Service/destination ports do not match!", target, d, status)
		}
	}
}
*/
