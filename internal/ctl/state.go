package ctl

import "time"

// Stats holds the daemon counters.
type Stats struct {
	Packets     uint64 `json:"packets"`     // packets from the queue
	Answers     uint64 `json:"answers"`     // DNS answers with addresses
	Claimed     uint64 `json:"claimed"`     // of those, matched a rule
	Changes     uint64 `json:"changes"`     // address set changes
	NotDNS      uint64 `json:"notDNS"`      // not UDP from port 53
	Malformed   uint64 `json:"malformed"`   // DNS failed to parse
	Skipped     uint64 `json:"skipped"`     // query, error, truncated answer, answer without addresses
	BadName     uint64 `json:"badName"`     // queried name does not look like a domain name
	Dropped     uint64 `json:"dropped"`     // not recorded: memory is full
	ApplyErrors uint64 `json:"applyErrors"` // failures updating address sets and routes
}

// ExitState is the interface an exit currently goes through.
type ExitState struct {
	Name  string `json:"name"`
	Via   string `json:"via"`   // firmware interface name; empty means no live tunnels
	Known bool   `json:"known"` // the daemon has already queried the firmware
}

// Observation is a DNS answer and the decision made on it.
type Observation struct {
	At     time.Time `json:"at"`
	Client string    `json:"client"`
	Device string    `json:"device,omitempty"` // the device's name from the firmware, if known
	// Via is the IPv6 address the answer went to, when the device asked over IPv6: its IPv6
	// traffic is not routed, so it may go around the tunnel.
	Via    string `json:"via,omitempty"`
	Name   string `json:"name"`
	Action string `json:"action"`
	Line   int    `json:"line"` // 0 means default matched
}

// Answer is a DNS answer and the decision made on it, numbered in arrival order.
type Answer struct {
	Seq uint64 `json:"seq"`
	Observation
}

// Answers are the DNS answers newer than the one a page already has, newest first (the answers
// command).
type Answers struct {
	Epoch int64  `json:"epoch"` // when the daemon started: another value means another daemon
	Last  uint64 `json:"last"`  // the number of the newest answer
	// Full means the whole list: the page replaces its own. So it is on its first request, after a
	// daemon restart, and when the answers it missed are no longer kept.
	Full    bool     `json:"full"`
	Answers []Answer `json:"answers"`
}

// State is the daemon state for the web page (the state command).
type State struct {
	Mode    string        `json:"mode"` // observe or route
	Started time.Time     `json:"started"`
	Rules   int           `json:"rules"`
	Addrs   int           `json:"addrs"`  // addresses in memory
	Claims  int           `json:"claims"` // claims
	Stats   Stats         `json:"stats"`
	Exits   []ExitState   `json:"exits"`
	Recent  []Observation `json:"recent"` // newest first
}
