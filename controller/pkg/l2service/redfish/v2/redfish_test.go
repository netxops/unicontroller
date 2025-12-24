package v2

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestFetchAll(t *testing.T) {
	Convey("Basic Example", t, func() {
		config := &Config{
			Host:     "https://192.168.10.201",
			Insecure: true,
			// SkipAuth: true,
			Username: "root",
			Password: "calvin",
		}
		client, err := Connect(config)
		So(err, ShouldBeNil)
		data := client.FetchAll()
		fmt.Println("-----", data)
		// So(data.SerialNumber, ShouldEqual, "9800115601645935")
	})
}
