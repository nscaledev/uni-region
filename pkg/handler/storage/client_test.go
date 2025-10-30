package storage

import (
	"context"
	"testing"

	"github.com/unikorn-cloud/region/pkg/client"
)

// What are the errs we expect here?
func TestGet(t testing.T) {
	c := newTestClient(t)
	c.Get(context.Background(), "org", "proj", "stor")

}

func TestUpdate(testing.T) {

}

func TestReboot(t testing.T) {

}

func TestStart(t testing.T) {

}

func TestStop(t testing.T) {

}

func TestDelete(t testing.T) {

}

func newTestClient(t testing.T) *Client {

	return NewClient(client.Client{}, "testnamespace")
}
