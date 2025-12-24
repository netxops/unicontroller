package workorderDir

//
// import (
// "context"
// "fmt"
// "github.com/netxops/unify/cmd/l2nodemap/service"
// "github.com/influxdata/telegraf/controller/global"
// "path"
// "regexp"
// "strings"
//
// etcd_client "github.com/rpcxio/rpcx-etcd/client"
// "github.com/smallnest/rpcx/client"
// )
//
// const (
// SYNC = "SYNC"
// )
//
// type SyncServiceUtils struct {
// ServiceName string
// DataMap     map[string]string
// }
//
// func NewSyncServiceUtils(service_name string) *SyncServiceUtils {
// return &SyncServiceUtils{
// ServiceName: service_name,
// }
// }
//
// func (s *SyncServiceUtils) makeServiceArgs(serviceType service.SyncServerType, options ...string) *service.SyncArgs {
// return &service.SyncArgs{
// ServiceType: serviceType,
// Id:          10,
// Ip:          "10.0.0.0",
// StructType:  "string",
// Platform:    "string",
// }
// }
//
// func (s *SyncServiceUtils) Call(serviceName string, args *service.SyncArgs) (*service.Reply, error) {
// d, err := etcd_client.NewEtcdDiscovery(global.GVA_CONFIG.Rpcx.BasePath, "SyncFileService", []string{global.GVA_CONFIG.Etcd.Addr}, nil)
// if err != nil {
// return nil, err
// }
// xclient := client.NewXClient("SyncFileService", client.Failover, client.RoundRobin, d, client.DefaultOption)
// defer xclient.Close()
//
// var reply interface{}
// switch serviceName {
// case SYNC:
// reply = &service.Reply{}
// err = xclient.Call(context.Background(), serviceName, args, reply)
// default:
// err = fmt.Errorf("unsupport SERVICE=%s", serviceName)
// }
//
// return reply.(*service.Reply), err
// }
//
// dataMap需要提供
// catalog如果是SDN，当前支持controller和site选择
// catalog如果是SWITCH或SERVER，可用vm来选择虚机，也可用tags、tenant、oob、device、nodemap、deviceRole、deviceType、rack、platform
// --------------需要用CATALOG进行大类区分，一级vc、tags、tenant、nodemap等选择项目
// catalog如果是VCENTER可通过vc和site进行选择
// 需要在输入时需要设置OUT_OF_BOUND、IN_BOUND，用于区分选择执行IP地址
// redfish设置用于指明执行REDFISH命令
//
// func (s *SyncServiceUtils) __SyncService(options ...string) (totalMap map[string][]map[string]string) {
// totalMap = make(map[string][]map[string]string)
// var serviceType service.SyncServerType
// LABEL:
// for key := range s.DataMap {
// switch strings.ToUpper(key) {
// case "DIR":
// serviceType = service.DIR
// break LABEL
// return
// case "GET":
// serviceType = service.GET
// break LABEL
// case "PUT":
// serviceType = service.PUT
// break LABEL
// }
// }
// if serviceType > 0 {
// args := s.makeServiceArgs(serviceType, options...)
// args.DataMap = s.DataMap
// reply, err := s.Call(s.ServiceName, args)
// if err != nil {
// fmt.Println("err:", err)
// } else {
// fmt.Println("file names:", reply.FileNameMap)
// fmt.Println("file data:", reply.FileData)
// }
// }
// return
// }
//
// func (s *SyncServiceUtils) SyncService(options ...string) (totalMap map[string][]map[string]string) {
// totalMap = make(map[string][]map[string]string)
// if _, ok := s.DataMap["dir"]; ok {
// if reply, err := s.GetResult(service.DIR, options...); err == nil {
// comply_list := []string{}
// un_comply_list := []string{}
// for _, file_name_list := range reply.FileNameMap {
// for _, file_name := range file_name_list {
// if path.Ext(file_name) == "" && validate_master_file(file_name) {
// comply_list = append(comply_list, file_name)
// } else {
// un_comply_list = append(un_comply_list, file_name)
// }
// }
// }
// fmt.Println("符合要求的文件夹:", comply_list)
// fmt.Println("不符合要求文件:", un_comply_list)
// } else {
// fmt.Println("remote call dir error:", err)
// }
// } else if get_value, ok := s.DataMap["get"]; ok {
// if reply, err := s.GetResult(service.GET, options...); err == nil {
// if len(reply.FileNameMap) > 0 {
// fmt.Println("file  list:", reply.FileNameMap)
// for _, file_name_list := range reply.FileNameMap {
// for _, file_name := range file_name_list {
// if fileValidate(get_value, file_name) {
// s.DataMap["get"] = path.Join(get_value, file_name)
// res, err := s.GetResult(service.GET, options...)
// if err == nil {
// fmt.Println("file  data:", res.FileData)
// } else {
// fmt.Printf("remote call get file(%s) error:%v\n", s.DataMap["get"], err)
// }
// }
// }
// }
// } else {
// fmt.Println("file  data:", reply.FileData)
// }
// } else {
// fmt.Printf("remote call get file(%s) error:%v\n", get_value, err)
// }
// } else if _, ok := s.DataMap["put"]; ok {
// if _, err := s.GetResult(service.PUT, options...); err == nil {
// fmt.Println("remote call put success")
// } else {
// fmt.Println("remote call put error:", err)
// }
// }
// return
// }
//
// func (s *SyncServiceUtils) GetResult(serviceType service.SyncServerType, options ...string) (reply *service.Reply, err error) {
// args := s.makeServiceArgs(serviceType, options...)
// args.DataMap = s.DataMap
// reply, err = s.Call(s.ServiceName, args)
// return
//
// }
//
// func validate_master_file(f string) bool {
// r := regexp.MustCompile("^-[\u4e00-\u9fa5]+?")
// if l := strings.Split(f, "(全)"); len(l) > 1 {
// return r.MatchString(strings.TrimSpace(l[1]))
// } else if l := strings.Split(f, "（全）"); len(l) > 1 {
// return r.MatchString(strings.TrimSpace(l[1]))
// } else {
// return false
// }
// }
//
// func fileValidate(path_name, file_name string) bool {
// suf := path.Ext(file_name)
// base_name := strings.TrimSuffix(file_name, suf)
// if strings.ToLower(suf) == ".csv" && strings.Contains(path_name, base_name) {
// return true
// }
// return false
// }
