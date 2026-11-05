// Package ctcheck is a dudect-style timing test (Reparaz, Balasch,
// Verbauwhede, "Dude, is my code constant time?", 2017): it times an
// operation on two classes of secret inputs, interleaved at random, and
// compares the two timing distributions with Welch's t-test. The timing tests
// themselves are behind the ctcheck build tag.
package ctcheck

import (
	"math"
	"math/rand/v2"
	"slices"
	"time"
)

// Threshold is the |t| above which the two classes differ in time: a leak.
const Threshold = 10

const (
	warmup   = 1000                 // samples that set the crop thresholds and are not counted
	minBatch = 2 * time.Microsecond // shortest timed batch, well above the clock resolution
)

// crops are the percentiles of the warm-up timings above which samples are
// dropped, one t-test per percentile: cropping removes the long tail of
// interrupts and GC pauses that hides a small shift in the bulk.
var crops = []float64{0.50, 0.75, 0.90, 0.95, 0.99}

// Result is the outcome of Run.
type Result struct {
	// T is the largest |t| over the uncropped samples and each crop.
	T float64
	// Samples is the number of samples counted, after warm-up.
	Samples int
	// Batch is the number of calls of op per timed sample.
	Batch int
}

// Run times op on samples inputs, each built by input before timing starts
// with a class, 0 or 1, chosen at random per sample. One sample is the time
// of Batch calls of op on its input, with Batch calibrated so that a batch on
// the input of one class or the other lasts at least 2 µs. The first 1000
// samples are warm-up; samples must exceed that. If a t-test cannot be
// computed, Result.T is +Inf.
func Run[T any](samples int, input func(class int) T, op func(T)) Result {
	if samples <= warmup {
		panic("ctcheck: samples must exceed the warm-up of 1000")
	}
	classes := make([]int, samples)
	inputs := make([]T, samples)
	for i := range samples {
		classes[i] = rand.IntN(2) //nolint:gosec // G404: class order, not a secret
		inputs[i] = input(classes[i])
	}
	batch := calibrate([2]T{input(0), input(1)}, op)

	times := make([]float64, samples)
	for i, in := range inputs {
		start := time.Now()
		for range batch {
			op(in)
		}
		times[i] = float64(time.Since(start))
	}

	sorted := slices.Sorted(slices.Values(times[:warmup]))
	limits := []float64{math.Inf(1)}
	for _, p := range crops {
		limits = append(limits, sorted[int(p*(warmup-1))])
	}
	tests := make([]welch, len(limits))
	for i := warmup; i < samples; i++ {
		for j, limit := range limits {
			if times[i] <= limit {
				tests[j].push(times[i], classes[i])
			}
		}
	}

	return Result{T: maxAbsT(tests), Samples: samples - warmup, Batch: batch}
}

// maxAbsT is the largest |t| over the tests. A test with no value (NaN: fewer
// than two samples in a class) makes it +Inf: the comparison "t > max" is
// false for NaN, so skipping it would let a broken measurement pass.
func maxAbsT(tests []welch) float64 {
	var maxT float64
	for _, w := range tests {
		t := math.Abs(w.t())
		if math.IsNaN(t) {
			return math.Inf(1)
		}
		maxT = max(maxT, t)
	}
	return maxT
}

// calibrate doubles the batch from 1 until a batch on the input of either
// class takes minBatch, by the fastest of five timings so that one preempted
// timing does not end the doubling early. Either class, not class 0 alone: on
// a leaking op the batch sized for the fast class makes every sample of the
// slow class many times longer, and the test runs for hours instead of failing.
func calibrate[T any](ins [2]T, op func(T)) int {
	for batch := 1; ; batch *= 2 {
		for _, in := range ins {
			fastest := time.Duration(math.MaxInt64)
			for range 5 {
				start := time.Now()
				for range batch {
					op(in)
				}
				fastest = min(fastest, time.Since(start))
			}
			if fastest >= minBatch {
				return batch
			}
		}
	}
}

// welch accumulates the mean and variance of each class online (Welford)
// for Welch's t-test.
type welch struct {
	n, mean, m2 [2]float64
}

func (w *welch) push(x float64, class int) {
	w.n[class]++
	d := x - w.mean[class]
	w.mean[class] += d / w.n[class]
	w.m2[class] += d * (x - w.mean[class])
}

// t is Welch's statistic (mean0 − mean1) / √(var0/n0 + var1/n1) with the
// sample variances; NaN with fewer than two samples in a class.
func (w *welch) t() float64 {
	v0 := w.m2[0] / (w.n[0] - 1)
	v1 := w.m2[1] / (w.n[1] - 1)
	return (w.mean[0] - w.mean[1]) / math.Sqrt(v0/w.n[0]+v1/w.n[1])
}
