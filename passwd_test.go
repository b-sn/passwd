package passwd_test

import (
	"testing"

	"github.com/b-sn/passwd"
	"github.com/sethvargo/go-password/password"
)

var R1 func(size uint8) string
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
