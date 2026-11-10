package trivy

import (
	"context"
	"testing"
	"time"
)

func TestParallelBound(t *testing.T) {
	t.Cleanup(func() { SetParallel(0) })
	SetParallel(1)
	rel, err := acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := acquire(ctx); err == nil {
		t.Fatal("a second match ran past a bound of 1")
	}
	SetParallel(2) // a new bound; the match running under the old one releases there
	rel2, err := acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rel()
	rel2()
	SetParallel(0)
	for range 3 {
		if _, err := acquire(context.Background()); err != nil {
			t.Fatal("unbounded match waited")
		}
	}
}
