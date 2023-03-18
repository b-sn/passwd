package passwd_test

import (
	"math"
	"regexp"
	"testing"

	"github.com/b-sn/passwd"
	"github.com/sethvargo/go-password/password"
)

var R1 func(size uint16) string
var R2 string

func BenchmarkGeneratingPasswd_SetTemplate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		R1 = passwd.GetGenerator()
	}
}

func BenchmarkGeneratingPasswd_Generate(b *testing.B) {
	R1 = passwd.GetGenerator()
	for i := 0; i < b.N; i++ {
		R1(64)
	}
}

func BenchmarkGeneratingGoPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		R2, _ = password.Generate(64, 10, 10, false, true)
	}
}

func TestMyCharSet(t *testing.T) {
	t.Parallel()
	tData := []struct {
		Param    string
		Expected passwd.CharSet
		Name     string
	}{
		{Param: "", Expected: passwd.CharSet{0, 0, 0, 0, 0, 0, 0, 0}, Name: "Empty string"},
		{Param: " !\"#$%&'()*+,-./0123456789:;<=>?", Expected: passwd.CharSet{0, uint32(math.Pow(2, 32)) - 1, 0, 0, 0, 0, 0, 0}, Name: "From 32 to 63 bits"},
		{Param: "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_", Expected: passwd.CharSet{0, 0, uint32(math.Pow(2, 32)) - 1, 0, 0, 0, 0, 0}, Name: "From 64 to 95 bits"},
		{Param: "`abcdefghijklmnopqrstuvwxyz{|}~", Expected: passwd.CharSet{0, 0, 0, uint32(math.Pow(2, 31)) - 1, 0, 0, 0, 0}, Name: "From 96 to 126 bits"},
	}
	for _, tCase := range tData {
		v := tCase
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			res := passwd.MyCharSet(v.Param)
			if res != v.Expected {
				t.Errorf("%s got = %v; expected %v", v.Name, res, v.Expected)
			}
		})
	}
}

func TestCharSets(t *testing.T) {
	t.Parallel()
	tData := []struct {
		Param    string
		Expected passwd.CharSet
		Name     string
	}{
		{Param: "qwertyuiopasdfghjklzxcvbnm", Expected: passwd.LowerLetters, Name: "Lower case"},
		{Param: "QWERTYUIOPASDFGHJKLZXCVBNM", Expected: passwd.UpperLetters, Name: "Upper case"},
		{Param: "1234567890", Expected: passwd.Numeric, Name: "Numeric"},
		{Param: ";!.+?~&'%=*#@$^:\",", Expected: passwd.Special, Name: "Special symbols"},
		{Param: "(){}[]<>", Expected: passwd.Brackets, Name: "Brackets"},
		{Param: "-", Expected: passwd.Minus, Name: "Minus"},
		{Param: "_", Expected: passwd.Underline, Name: "Underline"},
		{Param: " ", Expected: passwd.Space, Name: "Space"},
	}
	for _, tCase := range tData {
		v := tCase
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			res := passwd.MyCharSet(v.Param)
			if res != v.Expected {
				t.Errorf("%s charset = %v; expected %v", v.Name, res, v.Expected)
			}
		})
	}
}

func TestMergeSets(t *testing.T) {
	t.Parallel()
	tData := []struct {
		Param    []passwd.CharSet
		Expected passwd.CharSet
		Name     string
	}{
		{Param: []passwd.CharSet{passwd.LowerLetters, passwd.UpperLetters}, Expected: passwd.AllLetters, Name: "All case letters"},
		{Param: []passwd.CharSet{passwd.LowerLetters, passwd.UpperLetters, passwd.Numeric}, Expected: passwd.AlphaNumeric, Name: "All case letters and numbers 1"},
		{Param: []passwd.CharSet{passwd.AllLetters, passwd.Numeric}, Expected: passwd.AlphaNumeric, Name: "All case letters and numbers 2"},
		{Param: []passwd.CharSet{passwd.AllLetters, passwd.Numeric, passwd.Special, passwd.Underline}, Expected: passwd.Strong, Name: "Set for strong password 1"},
		{Param: []passwd.CharSet{passwd.AlphaNumeric, passwd.Special, passwd.Underline}, Expected: passwd.Strong, Name: "Set for strong password 2"},
		{Param: []passwd.CharSet{passwd.Minus, passwd.Space}, Expected: passwd.CharSet{0, 8193}, Name: "Minus plus Space"},
		{Param: []passwd.CharSet{passwd.LowerLetters, passwd.LowerLetters}, Expected: passwd.LowerLetters, Name: "Merge same sets"},
		{Param: []passwd.CharSet{{}, {}}, Expected: passwd.CharSet{0, 0, 0, 0, 0, 0, 0, 0}, Name: "Merge empty sets"},
		{Param: []passwd.CharSet{{1, 1, 1, 1, 2, 0, 0, 0}, {0, 0, 0, 2, 1, 1, 1, 1}}, Expected: passwd.CharSet{1, 1, 1, 3, 3, 1, 1, 1}, Name: "Merge another sets"},
	}
	for _, tCase := range tData {
		v := tCase
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			res := passwd.MergeSets(v.Param)
			if res != v.Expected {
				t.Errorf("%s charset = %v; expected %v", v.Name, res, v.Expected)
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	t.Parallel()
	tData := []struct {
		CharSet  []passwd.CharSet
		Length   uint16
		Expected regexp.Regexp
		Name     string
	}{
		{CharSet: []passwd.CharSet{passwd.LowerLetters}, Length: 10, Expected: *regexp.MustCompile(`^[a-z]{10}$`), Name: "Lower case letters"},
		{CharSet: []passwd.CharSet{passwd.UpperLetters}, Length: 100, Expected: *regexp.MustCompile(`^[A-Z]{100}$`), Name: "Upper case letters"},
		{CharSet: []passwd.CharSet{passwd.Numeric}, Length: 33, Expected: *regexp.MustCompile(`^[0-9]{33}$`), Name: "Numeric"},
		{CharSet: []passwd.CharSet{passwd.Space}, Length: 15, Expected: *regexp.MustCompile(`^\s{15}$`), Name: "Space"},
		{CharSet: []passwd.CharSet{passwd.Underline, passwd.Minus}, Length: 50, Expected: *regexp.MustCompile(`^[-_]{50}$`), Name: "Minus and underline"},
		{CharSet: []passwd.CharSet{passwd.MyCharSet("#")}, Length: 1, Expected: *regexp.MustCompile(`^#$`), Name: "Sharp"},
		{CharSet: []passwd.CharSet{passwd.Strong}, Length: 0, Expected: *regexp.MustCompile(`^$`), Name: "Empty string"},
	}
	for _, tCase := range tData {
		v := tCase
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			generator := passwd.GetGenerator(v.CharSet...)
			res := generator(v.Length)
			if !v.Expected.MatchString(res) {
				t.Errorf("%s charset = %v; expected %v", v.Name, res, v.Expected)
			}
		})
	}
}
