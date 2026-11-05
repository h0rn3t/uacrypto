package kalyna

import (
	"math"
	"slices"
	"testing"
)

func TestIncrementLE(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want []byte }{
		{[]byte{0x00, 0x00}, []byte{0x01, 0x00}},
		{[]byte{0xff, 0x00}, []byte{0x00, 0x01}},
		{[]byte{0xff, 0x01}, []byte{0x00, 0x02}},
		{[]byte{0xff, 0xff, 0xff}, []byte{0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		got := slices.Clone(tt.in)
		incrementLE(got)
		if !slices.Equal(got, tt.want) {
			t.Errorf("incrementLE(%x) = %x, want %x", tt.in, got, tt.want)
		}
	}
}

func TestModeLengthBounds(t *testing.T) {
	t.Parallel()
	for _, n := range []int{-1, 0, 1, math.MaxInt} {
		wantErr := n < 0 || uint64(n) > math.MaxUint32
		if err := fitsUint32(n); (err != nil) != wantErr {
			t.Errorf("fitsUint32(%d) error = %v, want error presence %v", n, err, wantErr)
		}
	}
	maxUint32 := uint64(math.MaxUint32)
	if maxUint32 < uint64(math.MaxInt) {
		if err := fitsUint32(int(maxUint32)); err != nil {
			t.Errorf("fitsUint32(%d) error = %v, want nil", maxUint32, err)
		}
		if err := fitsUint32(int(maxUint32 + 1)); err == nil {
			t.Errorf("fitsUint32(%d) error = nil, want error", maxUint32+1)
		}
	}
	limit := int(min(uint64(math.MaxUint32), uint64(math.MaxInt))/6) + 1
	steps, err := wrapSteps(limit)
	if err != nil || steps != (limit-1)*6 {
		t.Errorf("wrapSteps(%d) = %d, %v; want %d, nil", limit, steps, err, (limit-1)*6)
	}
	for _, halves := range []int{0, 1, limit + 1, math.MaxInt} {
		if steps, err := wrapSteps(halves); err == nil {
			t.Errorf("wrapSteps(%d) = %d, nil; want error", halves, steps)
		}
	}
}
