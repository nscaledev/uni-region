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

func newTestClient(t testing.T) *Client {

	return NewClient(client.Client{}, "testnamespace")
}
