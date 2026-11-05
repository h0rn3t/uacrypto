package ctcheck

import "testing"

var sink int

// spin does n rounds of work the compiler cannot drop.
func spin(n int) {
	for i := range n {
		sink += i ^ sink
	}
}

func TestRunDetectsLeak(t *testing.T) {
	// Class 1 does a hundred times the work of class 0: a leak no harness
	// can miss, measured in well under a second.
	r := Run(warmup+1000, func(class int) int { return 10 + 990*class }, spin)
	if r.Samples != 1000 {
		t.Errorf("Run(2000 samples).Samples = %d, want 1000", r.Samples)
	}
	if r.Batch < 1 {
		t.Errorf("Run(2000 samples).Batch = %d, want at least 1", r.Batch)
	}
	if r.T <= Threshold {
		t.Errorf("Run on a leaking op: |t| = %.2f, want above %d", r.T, Threshold)
	}
}

func TestRunRejectsTooFewSamples(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("Run(%d samples) did not panic, want a panic", warmup)
		}
	}()
	Run(warmup, func(int) int { return 0 }, spin)
}
