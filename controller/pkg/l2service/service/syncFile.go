package service

// type SYNCFILE struct {
// 	Path      string
// 	ExcelPath string
// }

// func (sf *SYNCFILE) SyncFile(ctx context.Context, args *structs.SyncArgs, reply *structs.SyncReply) error {
// 	fmt.Println("server type > ", args.ServiceType)
// 	switch args.ServiceType { // 工单文件夹
// 	case structs.DIR:
// 		fmt.Println("==========>>", sf.Path)
// 		data, _, err := readF.GetHomeFileOrDirNames(sf.Path)
// 		if err != nil {
// 			// global.LOG.Error("get file or dir list error:", zap.Any("", err))
// 			return err
// 		}
// 		reply.FileNameMap = data
// 		reply.MasterKey = sf.Path
// 		// global.LOG.Info("file or dir list:", zap.Any("", data))
// 	case structs.GET:
// 		if _, ok := args.DataMap["get"]; ok {
// 			fileData, nameList, filesInfoMap, err := readF.GetFileData(args.DataMap, sf.Path)
// 			if err != nil {
// 				// global.LOG.Error("get file data error:", zap.Any("", err))
// 				return err
// 			}
// 			reply.FileData = fileData
// 			reply.FileNameMap = nameList
// 			reply.FileSizeMap = filesInfoMap
// 			// global.LOG.Info("file data:", zap.Any("", fileData))
// 			// global.LOG.Info("file or dir list:", zap.Any("", nameList))
// 		} else {
// 			// global.LOG.Error("dataMap error:", zap.Any("", fmt.Errorf("路径为空")))
// 			return fmt.Errorf("路径为空")
// 		}
// 	case structs.PUT:
// 		csvInfo := args.CsvInfo
// 		readF.CreateWorkorderDir(csvInfo.CsvData, csvInfo.FileNameList, csvInfo.NewFolder, csvInfo.OldFolder, sf.Path)
// 		// var err error
// 		// if put_type, ok := args.DataMap["put"]; ok {
// 		// err = readF.ToCsv(put_type, sf.Path)
// 		// } else {
// 		// err = readF.ToCsv("add", sf.Path)
// 		// }
// 		// return err
// 	case structs.BULK_GET:
// 		pathMap := args.BulkGetPath
// 		if _, ok := args.DataMap["bulk_get"]; ok && len(pathMap) > 0 {
// 			fmt.Println("pathMap--->", pathMap)
// 			// map[string][][]string, map[string][]byte, error
// 			// csvDataMap以文件名为索引，数据是二维数组
// 			// zipDataMap以文件名为索引，数据zip压缩后的[]byte
// 			csvDataMap, zipDataMap, err := readF.BulkGetFileData(pathMap, sf.Path)
// 			if err != nil {
// 				return err
// 			}
// 			reply.ZipDataMap = zipDataMap
// 			reply.FileData = csvDataMap
// 		}
// 	case structs.IPAddressManager:
// 		err, data := readF.IpaddressManage(sf.ExcelPath)
// 		if err != nil {
// 			fmt.Println("IP EXCEL error---", err)
// 			return err
// 		}
// 		reply.FileData = data
// 	case structs.WorkorderDir:
// 		workorderPath := sf.Path
// 		data, err := readF.WorkorderDir(workorderPath)
// 		if err != nil {
// 			fmt.Println("workorder error---", err)
// 			return err
// 		}
// 		reply.WorkorderData = data
// 	default:
// 		fmt.Println("do nothing")
// 	}

// 	// IP地址管理文件

// 	return nil
// }
