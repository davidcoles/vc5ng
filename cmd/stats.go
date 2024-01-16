package main

import (
	"net/netip"
	"time"
)

/**********************************************************************/
// Stats
/**********************************************************************/

type Serv struct {
	Name         string     `json:"name,omitempty"`
	Description  string     `json:"description"`
	Address      netip.Addr `json:"address"`
	Port         uint16     `json:"port"`
	Protocol     protocol   `json:"protocol"`
	Required     uint8      `json:"required"`
	Available    uint8      `json:"available"`
	Stats        Stats      `json:"stats"`
	Destinations []Dest     `json:"destinations,omitempty"`
	Up           bool       `json:"up"`
	For          uint64     `json:"for"`
	Last         uint64     `json:"last"`
}

type Dest struct {
	Address    netip.Addr `json:"address"`
	Port       uint16     `json:"port"`
	Stats      Stats      `json:"stats"`
	Weight     uint8      `json:"weight"`
	Disabled   bool       `json:"disabled"`
	Up         bool       `json:"up"`
	For        uint64     `json:"for"`
	Took       uint64     `json:"took"`
	When       uint64     `json:"when"`
	Last       uint64     `json:"last"`
	Diagnostic string     `json:"diagnostic"`
	MAC        string     `json:"mac"`
}

type Key struct {
	VIP      netip.Addr
	RIP      netip.Addr
	Port     uint16
	Protocol uint8
}

type State struct {
	up   bool
	time time.Time
}

type Stats struct {
	Octets           uint64 `json:"octets"`
	Packets          uint64 `json:"packets"`
	Flows            uint64 `json:"flows"`
	Current          uint64 `json:"current"`
	OctetsPerSecond  uint64 `json:"octets_per_second"`
	PacketsPerSecond uint64 `json:"packets_per_second"`
	FlowsPerSecond   uint64 `json:"flows_per_second"`
	time             time.Time
}

type Summary struct {
	Uptime             uint64 `json:"uptime"`
	Latency            uint64 `json:"latency_ns"`
	Dropped            uint64 `json:"dropped"`
	Blocked            uint64 `json:"blocked"`
	NotQueued          uint64 `json:"notqueued"`
	DroppedPerSecond   uint64 `json:"dropped_per_second"`
	BlockedPerSecond   uint64 `json:"blocked_per_second"`
	NotQueuedPerSecond uint64 `json:"notqueued_per_second"`

	Octets           uint64 `json:"octets"`
	Packets          uint64 `json:"packets"`
	Flows            uint64 `json:"flows"`
	Current          uint64 `json:"current"`
	OctetsPerSecond  uint64 `json:"octets_per_second"`
	PacketsPerSecond uint64 `json:"packets_per_second"`
	FlowsPerSecond   uint64 `json:"flows_per_second"`
	time             time.Time
}

func (s *Stats) add(x Stats) {
	s.Octets += x.Octets
	s.Packets += x.Packets
	s.Flows += x.Flows
	s.Current += x.Current
	s.OctetsPerSecond += x.OctetsPerSecond
	s.PacketsPerSecond += x.PacketsPerSecond
	s.FlowsPerSecond += x.FlowsPerSecond
}
