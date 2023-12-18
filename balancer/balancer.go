package balancer

import (
	"log"
	"net/netip"

	"github.com/davidcoles/xvs"

	"github.com/davidcoles/vc5ng"
)

type Balancer struct {
	Client  *xvs.Client
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
			b.Client.UpdateDestination(xs, xvs.Destination{Address: d.Destination.Address, Weight: status.HealthyWeight()})
		} else {
			b.Client.RemoveDestination(xs, d.Destination) // exists in XVS, but not in target config - delete
		}
		delete(target.Destinations, key)
	}

	for d, status := range target.Destinations {
		// was not handled so does not exist in XVS - create
		if d.Port == xs.Port {
			b.Client.CreateDestination(xs, xvs.Destination{Address: d.Addr, Weight: status.HealthyWeight()})
		} else {
			log.Println("Service/destination ports do not match!", target, d, status)
		}
	}
}
