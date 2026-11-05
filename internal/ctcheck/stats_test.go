package ctcheck

import (
	"math"
	"testing"
)

func TestWelchKnownValues(t *testing.T) {
	// Class 0 {1,2,3,4,5}: mean 3, sample variance 10/4 = 2.5.
	// Class 1 {2,4,6,8,10}: mean 6, sample variance 40/4 = 10.
	// t = (3 − 6) / √(2.5/5 + 10/5) = −3 / √2.5 = −1.897 to 3 decimals.
	var w welch
	for _, x := range []float64{1, 2, 3, 4, 5} {
		w.push(x, 0)
	}
	for _, x := range []float64{2, 4, 6, 8, 10} {
		w.push(x, 1)
	}
	if got := w.t(); math.Abs(got-(-1.897)) > 0.0005 {
		t.Errorf("welch.t() = %.4f, want -1.897", got)
	}
}
