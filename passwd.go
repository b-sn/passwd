package passwd

import (
	"crypto/rand"
)

type CharSet [8]uint32

// Sets of characters that can be used to generate passwords
var (
	LowerLetters = CharSet{0, 0, 0, 134217726}                    // a-z
	UpperLetters = CharSet{0, 0, 134217726}                       // A-Z
	AllLetters   = CharSet{0, 0, 134217726, 134217726}            // A-Za-z
	Numeric      = CharSet{0, 67043328}                           // 0-9
	AlphaNumeric = CharSet{0, 67043328, 134217726, 134217726}     // 0-9A-Za-z
	Special      = CharSet{0, 2885704958, 1073741825, 1073741824} // ;!.+?~&'%=*#@$^:",
	Brackets     = CharSet{0, 1342178048, 671088640, 671088640}   // (){}[]<>
	Minus        = CharSet{0, 8192}                               // "-"
	Underline    = CharSet{0, 0, 2147483648}                      // "_"
	Space        = CharSet{0, 1}                                  // " "
	Strong       = CharSet{0, 2952748286, 3355443199, 1207959550} // AlphaNumeric + Special + Underline
)

// Create a own CharSet from a string
func MyCharSet(s string) (mask CharSet) {
	for _, ch := range s {
		mask[ch/32] |= 1 << (uint32(ch) % 32)
	}
	return
}

// Merge multiple CharSets into one
func MergeSets(sets []CharSet) CharSet {

	if len(sets) == 0 {
		sets = []CharSet{Strong}
	}

	var res CharSet = sets[0]

	for _, set := range sets[1:] {
		for i, val := range set {
			res[i] |= val
		}
	}

	return res
}

// Get a random string generator
func GetGenerator(sets ...CharSet) func(size uint16) string {

	var mask CharSet = MergeSets(sets)

	return func(size uint16) string {
		if size == 0 {
			return ""
		}
		res := make([]byte, size)
		buffer := make([]byte, int(size)*4)

		for {
			_, err := rand.Read(buffer)
			if err != nil {
				return ""
			}
			for _, ch := range buffer {
				if (mask[ch/32]>>(ch%32))&1 == 0 {
					continue
				}
				size--
				res[size] = ch
				if size == 0 {
					return string(res)
				}
			}
		}
	}
}
