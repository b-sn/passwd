# Golang password generator

## Usage

```go
import "github.com/b-sn/passwd"

func main() {
    generatePass1 := passwd.GetGenerator(passwd.Strong)
    fmt.Println(generatePass1(12))
    fmt.Println(generatePass1(24))

    generatePass2 := passwd.GetGenerator(passwd.Numeric, passwd.MyCharSet("ABC"))
    fmt.Println(generatePass2(36))
}
```

### Output:

```
uk2R.Pgy4,eK
'WC^X81?3cV_VL6=Xs19!xHu
A43182271C79BC105C5126A74A1840521244
```

