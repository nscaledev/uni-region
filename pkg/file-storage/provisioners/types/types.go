package types

import (
	"net"

	"k8s.io/apimachinery/pkg/api/resource"
)

type FileStorageDetails struct {
	Size              *resource.Quantity
	Path              string
	RootSquashEnabled bool
	UsedCapacity      *resource.Quantity
}

type FileStorageAttachments struct {
	Items []Attachment
}

type IPRange struct {
	Start net.IP
	End   net.IP
}

type Attachment struct {
	VlanID  int64
	IPRange *IPRange
}
