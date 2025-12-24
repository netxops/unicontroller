package firewall

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/name"
	"github.com/netxops/utils/validator"
)

const (
	MAX_NAME_LENGTH = 128
)

type Naming struct {
	name.NameStrategy
	node        FirewallNode
	nameService func(data interface{}) (string, error)
}

// type NamingType int
// const (
// _ NamingType = iota
// NAT
// POLICY
// OBJECT
// )

func NewNaming(node FirewallNode) *Naming {
	return &Naming{
		node: node,
	}
}

func (snn *Naming) Node() FirewallNode {
	return snn.node
}

func (snn *Naming) WithNameService(f func(data interface{}) (string, error)) *Naming {
	snn.nameService = f
	return snn
}

type SRXNameingInputValidator struct{}

func (aiv SRXNameingInputValidator) Validate(data map[string]interface{}) validator.Result {
	input := data["input"]
	// input.(*name.NetworkNamingInput)
	switch input.(type) {
	case *name.NetworkNamingInput:
		if input.(*name.NetworkNamingInput).Group.IsEmpty() {
			return validator.NewValidateResult(false, "address group is empty")
		}

	case *name.ServiceNamingInput:
		if input.(*name.ServiceNamingInput).Service.IsEmpty() {
			return validator.NewValidateResult(false, "service is empty")
		}
	}
	if input.(name.NamingInput).Intent() == nil {
		return validator.NewValidateResult(false, "intent is empty")
	}

	return validator.NewValidateResult(true, "")
}

func (snn *Naming) NewName(data interface{}, ruleType name.NamingRuleType) (string, error) {
	if snn.nameService != nil {
		return snn.nameService(data)
	}

	var formatter *name.Formatter

	switch data.(type) {
	case *name.NetworkNamingInput:
		input := data.(*name.NetworkNamingInput)
		formatter = snn.Formatter(input.Selector())
	case *name.ServiceNamingInput:
		input := data.(*name.ServiceNamingInput)
		formatter = snn.Formatter(input.Selector())
	case *name.PoolNamingInput:
		input := data.(*name.PoolNamingInput)
		formatter = snn.Formatter(input.Selector())
	case *name.VipNamingInput:
		input := data.(*name.VipNamingInput)
		formatter = snn.Formatter(input.Selector())
	case *name.PolicyNamingInput:
		input := data.(*name.PolicyNamingInput)
		formatter = snn.Formatter(input.Selector())
	default:
		return "", fmt.Errorf("unsupport naming input: %+v", data)
	}

	// input := data.(*name.NetworkNamingInput)
	// formatter := snn.Formatter(input.Selector())

	theName, err := formatter.Name(data)
	if err != nil {
		return theName, err
	}

	if snn.node.HasObjectName(theName) {
		for i := 1; i < 100; i++ {
			tmpName := fmt.Sprintf("%s%s%03d", theName, formatter.Sep, i)
			if !snn.node.HasObjectName(tmpName) {
				return tmpName, nil
			}
		}
		return theName, fmt.Errorf("name '%s' is exist", theName)

	} else {
		return theName, nil
	}
}

func (snn *Naming) NameService(data interface{}) (create, reuse string, err error) {
	result := SRXNameingInputValidator{}.Validate(map[string]interface{}{"input": data})
	if !result.Status() {
		err = fmt.Errorf("%s", result.Msg())
		return
	}

	input := data.(*name.ServiceNamingInput)
	// fmt.Printf("input.group:%+v\n", input.Group)
	// object, ok := snn.node.GetObjectByNetworkGroup(input.Group)
	switch input.Rule() {
	// case name.NEW_OBJECT_ONLY:

	case name.NEW:
		create, err = snn.NewName(data, input.Rule())
		return
	case name.REUSE_GROUP_ONLY:
		object, ok := snn.node.GetObjectByService(input.Service, SEARCH_GROUP)
		if !ok {
			err = fmt.Errorf("can not find object")
			return
		}
		if object.Type() == GROUP_SERVICE {
			reuse = object.Name()
			return
		} else {
			err = fmt.Errorf("object is not group network")
			return
		}
	case name.REUSE_OBJECT_ONLY:
		object, ok := snn.node.GetObjectByService(input.Service, SEARCH_OBJECT)
		if !ok {
			err = fmt.Errorf("can not find object")
			return
		}
		if object.Type() == OBJECT_SERVICE {
			reuse = object.Name()
		} else {
			err = fmt.Errorf("object is not object network")
			return
		}
	case name.REUSE_ONLY:
		object, ok := snn.node.GetObjectByService(input.Service, SEARCH_OBJECT_OR_GROUP)
		if !ok {
			err = fmt.Errorf("can not find object")
			return
		}
		reuse = object.Name()
		return
	case name.REUSE_GROUP_OR_NEW:
		object, ok := snn.node.GetObjectByService(input.Service, SEARCH_GROUP)

		if !ok {
			create, err = snn.NewName(data, input.Rule())
			return
		}
		if object.Type() == GROUP_SERVICE {
			reuse = object.Name()
			return
		} else {
			create, err = snn.NewName(data, input.Rule())
			return
		}

	case name.REUSE_OBJECT_OR_NEW:
		object, ok := snn.node.GetObjectByService(input.Service, SEARCH_OBJECT)
		if !ok {
			create, err = snn.NewName(data, input.Rule())
			return
		}

		if object.Type() == OBJECT_SERVICE {
			reuse = object.Name()
			return
		} else {
			create, err = snn.NewName(data, input.Rule())
			return
		}

	case name.REUSE_OR_NEW:
		object, ok := snn.node.GetObjectByService(input.Service, SEARCH_OBJECT_OR_GROUP)
		if !ok {
			create, err = snn.NewName(data, input.Rule())
			return
		}

		if object.Type() == OBJECT_SERVICE || object.Type() == GROUP_SERVICE {
			reuse = object.Name()
			return
		} else {
			create, err = snn.NewName(data, input.Rule())
			return
		}

	}
	// object, ok := snn.node.GetObjectByNetworkGroup(input.Group)

	return
}

func (snn *Naming) NamePool(data interface{}, natType NatType) (create, reuse string, err error) {
	result := SRXNameingInputValidator{}.Validate(map[string]interface{}{"input": data})
	if !result.Status() {
		err = fmt.Errorf("%s", result.Msg())
		return
	}

	input := data.(*name.PoolNamingInput)
	switch input.Rule() {
	case name.NEW:
		create, err = snn.NewName(data, input.Rule())
		return
	case name.REUSE_OR_NEW, name.REUSE_OBJECT_OR_NEW, name.REUSE_GROUP_OR_NEW, name.REUSE_POOL_OR_NEW:
		object, ok := snn.node.GetPoolByNetworkGroup(input.Group, natType)
		if !ok {
			create, err = snn.NewName(data, input.Rule())
			return
		}
		if object.Type() == OBJECT_POOL {
			reuse = object.Name()
			return
		} else {
			err = fmt.Errorf("object is not object pool")
			return
		}

	default:
		// case name.REUSE_OR_NEW:
		object, ok := snn.node.GetPoolByNetworkGroup(input.Group, natType)
		if !ok {
			err = fmt.Errorf("can not find object")
			return
		}
		if object.Type() == OBJECT_POOL {
			reuse = object.Name()
			return
		} else {
			err = fmt.Errorf("object is not object pool")
			return
		}
	}
}

func (snn *Naming) NameNetwork(data interface{}, port api.Port) (create, reuse string, err error) {
	result := SRXNameingInputValidator{}.Validate(map[string]interface{}{"input": data})
	if !result.Status() {
		err = fmt.Errorf("%s", result.Msg())
		return
	}

	input := data.(*name.NetworkNamingInput)
	// fmt.Printf("input.group:%+v\n", input.Group)
	// object, ok := snn.node.GetObjectByNetworkGroup(input.Group)
	switch input.Rule() {
	case name.NEW:
		create, err = snn.NewName(data, input.Rule())
		return
	case name.REUSE_GROUP_ONLY:
		object, ok := snn.node.GetObjectByNetworkGroup(input.Group, SEARCH_GROUP, port)
		if !ok {
			err = fmt.Errorf("can not find object")
			return
		}
		if object.Type() == GROUP_NETWORK {
			reuse = object.Name()
			return
		} else {
			err = fmt.Errorf("object is not group network")
			return
		}
	case name.REUSE_OBJECT_ONLY:
		object, ok := snn.node.GetObjectByNetworkGroup(input.Group, SEARCH_OBJECT, port)
		if !ok {
			err = fmt.Errorf("can not find object")
			return
		}
		if object.Type() == OBJECT_NETWORK {
			reuse = object.Name()
			return
		} else {
			err = fmt.Errorf("object is not object network")
			return
		}
	case name.REUSE_ONLY:
		object, ok := snn.node.GetObjectByNetworkGroup(input.Group, SEARCH_OBJECT_OR_GROUP, port)
		if !ok {
			err = fmt.Errorf("can not find object")
		}
		reuse = object.Name()
		return
	case name.REUSE_GROUP_OR_NEW:
		object, ok := snn.node.GetObjectByNetworkGroup(input.Group, SEARCH_GROUP, port)

		if !ok {
			create, err = snn.NewName(data, input.Rule())
			return
		}
		if object.Type() == GROUP_NETWORK {
			reuse = object.Name()
			return
		} else {
			create, err = snn.NewName(data, input.Rule())
			return
		}
	case name.REUSE_OBJECT_OR_NEW:
		object, ok := snn.node.GetObjectByNetworkGroup(input.Group, SEARCH_OBJECT, port)
		if !ok {
			create, err = snn.NewName(data, input.Rule())
			return
		}

		if object.Type() == OBJECT_NETWORK {
			reuse = object.Name()
			return
		} else {
			create, err = snn.NewName(data, input.Rule())
			return
		}

	case name.REUSE_OR_NEW:
		object, ok := snn.node.GetObjectByNetworkGroup(input.Group, SEARCH_OBJECT_OR_GROUP, port)
		if !ok {
			create, err = snn.NewName(data, input.Rule())
			return
		}

		if object.Type() == OBJECT_NETWORK || object.Type() == GROUP_NETWORK {
			reuse = object.Name()
		} else {
			create, err = snn.NewName(data, input.Rule())
			return
		}

	}

	// object, ok := snn.node.GetObjectByNetworkGroup(input.Group)

	return
}

func GetName(name, sep string, checkFunc func(string) bool) (string, error) {
	if !checkFunc(name) {
		return name, nil
	}

	for i := 1; i < 1000; i++ {
		n := fmt.Sprintf("%s%s%03d", name, sep, i)
		if !checkFunc(n) {
			return n, nil
		}
	}

	return "", fmt.Errorf("get name failed, name:%s", name)
}
