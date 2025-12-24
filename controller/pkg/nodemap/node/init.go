package node

func NodeInit() {
	//global.GVA_Register.Enrollment(constant.NODE_CONNECTOR_ID, &NodeConnector{})
	//global.GVA_Register.Enrollment(constant.DEVICE_NODE_ID, &DeviceNode{})
	//global.GVA_Register.Enrollment(constant.FHRP_GROUP_ID, &FhrpGroup{})
	//global.GVA_Register.Enrollment(constant.MEMBER_ID, &Member{})
	//global.GVA_Register.Enrollment(constant.NODE_VRF_ID, &NodeVrf{})
	//global.GVA_Register.Enrollment(constant.NODE_PORT_ID, &NodePort{})
}

// // InterfaceRegistry 用于存储接口类型到其具体实现的映射
// type InterfaceRegistry struct {
// 	registry map[reflect.Type]map[string]reflect.Type
// }

// // NewInterfaceRegistry 创建一个新的 InterfaceRegistry
// func NewInterfaceRegistry() *InterfaceRegistry {
// 	return &InterfaceRegistry{
// 		registry: make(map[reflect.Type]map[string]reflect.Type),
// 	}
// }

// func (r *InterfaceRegistry) RegisterType(interfaceType reflect.Type, name string, concreteType reflect.Type) {
// 	if r.registry[interfaceType] == nil {
// 		r.registry[interfaceType] = make(map[string]reflect.Type)
// 	}
// 	r.registry[interfaceType][name] = concreteType
// }

// func (r *InterfaceRegistry) GetType(interfaceType reflect.Type, name string) (reflect.Type, bool) {
// 	if implementations, ok := r.registry[interfaceType]; ok {
// 		if concreteType, ok := implementations[name]; ok {
// 			return concreteType, true
// 		}
// 	}
// 	return nil, false
// }

// var GlobalInterfaceRegistry = &InterfaceRegistry{
// 	registry: make(map[reflect.Type]map[string]reflect.Type),
// }

// // InterfacesToRawMessages 现在要求 T 实现 TypedInterface
// func InterfacesToRawMessages[T api.TypedInterface](interfaces []T) ([]json.RawMessage, error) {
// 	rawMessages := make([]json.RawMessage, len(interfaces))
// 	for i, v := range interfaces {
// 		typeName := v.TypeName() // 使用 TypedInterface 的 TypeName 方法
// 		data, err := json.Marshal(v)
// 		if err != nil {
// 			return nil, err
// 		}
// 		wrapper := struct {
// 			Type string          `json:"type"`
// 			Data json.RawMessage `json:"data"`
// 		}{
// 			Type: typeName,
// 			Data: data,
// 		}
// 		rawMessage, err := json.Marshal(wrapper)
// 		if err != nil {
// 			return nil, err
// 		}
// 		rawMessages[i] = rawMessage
// 	}
// 	return rawMessages, nil
// }

// // RawMessagesToInterfaces 也需要相应的修改
// func RawMessagesToInterfaces[T any](rawMessages []json.RawMessage) ([]T, error) {
// 	result := make([]T, len(rawMessages))
// 	for i, raw := range rawMessages {
// 		var wrapper struct {
// 			Type string          `json:"type"`
// 			Data json.RawMessage `json:"data"`
// 		}
// 		if err := json.Unmarshal(raw, &wrapper); err != nil {
// 			return nil, err
// 		}

// 		// 获取 T 的类型
// 		var zero T
// 		interfaceType := reflect.TypeOf(&zero).Elem()

// 		concreteType, ok := GlobalInterfaceRegistry.GetType(interfaceType, wrapper.Type)
// 		if !ok {
// 			return nil, fmt.Errorf("unknown type: %s", wrapper.Type)
// 		}

// 		value := reflect.New(concreteType).Interface()
// 		if err := json.Unmarshal(wrapper.Data, value); err != nil {
// 			return nil, err
// 		}

// 		result[i] = reflect.ValueOf(value).Interface().(T)
// 	}
// 	return result, nil
// }
