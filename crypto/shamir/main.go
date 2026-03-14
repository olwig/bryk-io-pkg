package shamir

import (
	"math/rand"
	"strconv"

	"go.bryk.io/pkg/errors"
)

const (
	// ShareOverhead is the byte size overhead of each share when using
	// Split on a secret. This is caused by appending a one byte tag to
	// the share.
	ShareOverhead = 1
)

// SplitOptions allows for configuration of the Split function.
// It can be used to set the maximum value for x coordinates and whether
// the x coordinates should be linear or random. The default maximum is 255,
// and the default is to use random x coordinates.
// Limit  which is not in the range of 2 to 255 will be set to 255.
// If linear is true, the x coordinates will be 1, 2, ..., max instead of random.
// Limit limits the maximum value for x coordinates, which must be at least 2 and at most 255.
// Possible use case: restricting the coordinate range when the index size
// is limited, e.g. a binary protocol where the index is only 4 bits.
type SplitOptions struct {
	Limit  int
	Linear bool
}

// Split takes an arbitrarily long secret and generates a `parts` number
// of shares, `threshold` of which are required to reconstruct the secret.
// The parts and threshold must be at least 2, and less than 256. The returned
// shares are each one byte longer than the secret as they attach a tag used
// to reconstruct the secret.
// The `opts` parameter can be used to configure the maximum value for x coordinates
// and whether the x coordinates should be linear or random. See SplitOptions for details.
// Possible use case: restricting the coordinate range when the index size
// is limited, e.g. a binary protocol where the index is only 4 bits.
func Split(secret []byte, parts, threshold int, opts ...SplitOptions) ([][]byte, error) {

	maxX, linearX := 255, false
	if len(opts) > 0 {
		if lim := opts[0].Limit; lim >= 2 && lim <= maxX {
			maxX = lim
		}
		linearX = opts[0].Linear
	}

	// Sanity check the input
	if parts < threshold {
		return nil, errors.New("parts cannot be less than threshold")
	}
	if parts > maxX {
		return nil, errors.New("parts cannot exceed the maximum value of " + strconv.Itoa(maxX))
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if threshold > maxX {
		return nil, errors.New("threshold cannot exceed " + strconv.Itoa(maxX))
	}
	if len(secret) == 0 {
		return nil, errors.New("cannot split an empty secret")
	}

	// Generate list of x coordinates linear/random and limited to maxX.
	var xCoordinates []int
	if !linearX {
		xCoordinates = rand.Perm(maxX)
	} else {
		xCoordinates = make([]int, maxX)
		for i := range xCoordinates {
			xCoordinates[i] = i
		}
	}

	// Allocate the output array, initialize the final byte
	// of the output with the offset. The representation of each
	// output is {y1, y2, .., yN, x}.
	out := make([][]byte, parts)
	for idx := range out {
		out[idx] = make([]byte, len(secret)+1)
		out[idx][len(secret)] = uint8(xCoordinates[idx]) + 1
	}

	// Construct a random polynomial for each byte of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	for idx, val := range secret {
		p, err := makePolynomial(val, uint8(threshold-1))
		if err != nil {
			return nil, errors.New("failed to generate polynomial")
		}

		// Generate a `parts` number of (x,y) pairs
		// We cheat by encoding the x value once as the final index,
		// so that it only needs to be stored once.
		for i := 0; i < parts; i++ {
			x := uint8(xCoordinates[i]) + 1
			y := p.evaluate(x)
			out[i][idx] = y
		}
	}

	// Return the encoded secrets
	return out, nil
}

// Combine is used to reverse a Split and reconstruct a secret once a
// `threshold` number of parts are available.
func Combine(parts [][]byte) ([]byte, error) {
	// Verify enough parts provided
	if len(parts) < 2 {
		return nil, errors.New("less than two parts cannot be used to reconstruct the secret")
	}

	// Verify the parts are all the same length
	firstPartLen := len(parts[0])
	if firstPartLen < 2 {
		return nil, errors.New("parts must be at least two bytes")
	}
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) != firstPartLen {
			return nil, errors.New("all parts must be the same length")
		}
	}

	// Create a buffer to store the reconstructed secret
	secret := make([]byte, firstPartLen-1)

	// Buffer to store the samples
	xSamples := make([]uint8, len(parts))
	ySamples := make([]uint8, len(parts))

	// Set the x value for each sample and ensure no x sample values are the same,
	// otherwise div() can be unhappy
	checkMap := make(map[byte]bool)
	for i, part := range parts {
		samp := part[firstPartLen-1]
		if exists := checkMap[samp]; exists {
			return nil, errors.New("duplicate part detected")
		}
		checkMap[samp] = true
		xSamples[i] = samp
	}

	// Reconstruct each byte
	for idx := range secret {
		// Set the y value for each sample
		for i, part := range parts {
			ySamples[i] = part[idx]
		}

		// Interpolate the polynomial and compute the value at 0
		val := interpolatePolynomial(xSamples, ySamples, 0)

		// Evaluate the 0th value to get the intercept
		secret[idx] = val
	}
	return secret, nil
}
