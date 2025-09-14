package main

import (
	"time"
)

// Flow represents a network flow
type Flow struct {
	Time        *time.Time `json:"time,omitempty"`
	Verdict     Verdict    `json:"verdict"`
	IP          *IP        `json:"ip,omitempty"`
	L4          *L4        `json:"l4,omitempty"`
	L7          *L7        `json:"l7,omitempty"`
	Type        FlowType   `json:"type"`
	Source      *Endpoint  `json:"source,omitempty"`
	Destination *Endpoint  `json:"destination,omitempty"`
}

// Verdict represents the verdict of a flow
type Verdict int32

const (
	Verdict_VERDICT_UNKNOWN Verdict = 0
	Verdict_FORWARDED       Verdict = 1
	Verdict_DROPPED         Verdict = 2
	Verdict_ERROR           Verdict = 3
)

func (v Verdict) String() string {
	switch v {
	case Verdict_FORWARDED:
		return "FORWARDED"
	case Verdict_DROPPED:
		return "DROPPED"
	case Verdict_ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// IP represents IP layer information
type IP struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// L4 represents Layer 4 information
type L4 struct {
	TCP *TCP `json:"tcp,omitempty"`
	UDP *UDP `json:"udp,omitempty"`
}

// TCP represents TCP information
type TCP struct {
	SourcePort      uint32    `json:"source_port"`
	DestinationPort uint32    `json:"destination_port"`
	Flags           *TCPFlags `json:"flags,omitempty"`
	Bytes           uint32    `json:"bytes"`
}

// UDP represents UDP information
type UDP struct {
	SourcePort      uint32 `json:"source_port"`
	DestinationPort uint32 `json:"destination_port"`
	Bytes           uint32 `json:"bytes"`
}

// TCPFlags represents TCP flags
type TCPFlags struct {
	SYN bool `json:"syn"`
	ACK bool `json:"ack"`
	FIN bool `json:"fin"`
	RST bool `json:"rst"`
	PSH bool `json:"psh"`
	URG bool `json:"urg"`
}

func (f *TCPFlags) String() string {
	var flags []string
	if f.SYN {
		flags = append(flags, "SYN")
	}
	if f.ACK {
		flags = append(flags, "ACK")
	}
	if f.FIN {
		flags = append(flags, "FIN")
	}
	if f.RST {
		flags = append(flags, "RST")
	}
	if f.PSH {
		flags = append(flags, "PSH")
	}
	if f.URG {
		flags = append(flags, "URG")
	}

	if len(flags) == 0 {
		return "NONE"
	}

	result := flags[0]
	for i := 1; i < len(flags); i++ {
		result += "," + flags[i]
	}
	return result
}

// L7 represents Layer 7 information
type L7 struct {
	Type L7Type `json:"type"`
}

// L7Type represents Layer 7 protocol type
type L7Type int32

const (
	L7Type_UNKNOWN_L7 L7Type = 0
	L7Type_HTTP       L7Type = 1
	L7Type_KAFKA      L7Type = 2
	L7Type_DNS        L7Type = 3
)

func (t L7Type) String() string {
	switch t {
	case L7Type_HTTP:
		return "HTTP"
	case L7Type_KAFKA:
		return "KAFKA"
	case L7Type_DNS:
		return "DNS"
	default:
		return "UNKNOWN"
	}
}

// FlowType represents the type of flow
type FlowType int32

const (
	FlowType_UNKNOWN_TYPE FlowType = 0
	FlowType_L3_L4        FlowType = 1
	FlowType_L7           FlowType = 2
)

func (t FlowType) String() string {
	switch t {
	case FlowType_L3_L4:
		return "L3_L4"
	case FlowType_L7:
		return "L7"
	default:
		return "UNKNOWN"
	}
}

// Endpoint represents a network endpoint with namespace information
type Endpoint struct {
	Namespace   string            `json:"namespace"`
	PodName     string            `json:"pod_name"`
	ServiceName string            `json:"service_name"`
	Workload    string            `json:"workload"`
	Labels      map[string]string `json:"labels"`
}
