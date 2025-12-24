package windows

//import (
//	"fmt"
//	"github.com/StackExchange/wmi"
//)
//
//type cpuInfo struct {
//	Name          string
//	NumberOfCores uint32
//	ThreadCount   uint32
//}
//
//func getCPUInfo() {
//
//	var cpuinfo []cpuInfo
//
//	err := wmi.Query("Select * from Win32_Processor", &cpuinfo)
//	if err != nil {
//		return
//	}
//	fmt.Printf("Cpu info =", cpuinfo)
//}
