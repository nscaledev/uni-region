package region

import (
	"context"
	"io"
)

//nolint:containedctx
type ContextReader struct {
	ctx   context.Context
	inner io.Reader
}

func NewContextReader(ctx context.Context, inner io.Reader) *ContextReader {
	return &ContextReader{
		ctx:   ctx,
		inner: inner,
	}
}

func (r *ContextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.inner.Read(p)
	}
}
