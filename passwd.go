package passwd

import (
	"crypto/rand"
)

type CharSet [8]uint32
type CharSets []CharSet

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

func MyCharSet(s string) CharSet {
	var mask CharSet
	for _, ch := range s {
		mask[ch/32] |= 1 << (uint32(ch) % 32)
	}
	return mask
}

func GetGenerator(charSets ...CharSet) func(size uint8) string {
	var mask CharSet
	for _, set := range charSets {
		for i := 0; i < 8; i++ {
			mask[i] |= set[i]
		}
	}

	return func(size uint8) string {
		res := make([]byte, size)
		var index uint8
		buffer := make([]byte, int(size)*4)

		for index < size {
			_, err := rand.Read(buffer)
			if err != nil {
				return ""
			}
			for i, ch := range buffer {
				if (mask[ch/32]>>(ch%32))&1 == 0 || i%3 != 0 {
					continue
				}
				res[index] = ch
				index++
				if index == size {
					break
				}
			}
		}
		return string(res)
	}
}
