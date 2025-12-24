package service

//
// func (ts *TOPO) SwitchVersion(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
//
//
// snmpTask, err := taskConfig.NewExecutor(remote)
// snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
// portIpTable, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
// if err != nil {
// xlog.Info("NormalPortIp.portIpTable", zap.Any("error", err))
// return nil, err
// }
// iftableSerivce := taskConfig.GetMainConfig().Select(remote, "iftable")
// iftableTable, err := iftableSerivce.Run(remote)
// if err != nil {
// xlog.Info("NormalPortIp.iftableTable", zap.Any("error", err))
// return nil, err
// }
// portIpTable.ForEach(PortIpIndexProcess)
// err = portIpTable.AddKeyFromTable("port", "interface", "name", "", iftableTable, "")
// if err != nil {
// xlog.Info("NormalPortIp.portIpTable", zap.Any("error", err))
// return nil, err
// }
// return portIpTable, nil
// }
//
