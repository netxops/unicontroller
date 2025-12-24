package nodemap

// intf = select_interface_by_network
// result = [intf]
// {"interface_list": result, "nodemap": self}
// 如何通过网络选择到了多个接口，验证接口的对端是同一台交换机
// type PortListIsSameNodeValidator struct {
// }
//
// func (psv *PortListIsSameNodeValidator) Validate(data map[string]interface{}) validator.Result {
// portList := data["portList"].([]*node.Port)
// var node []string
// for index, port := range portList {
// if index == 0 {
// node = port.FlattenPath()[0:2]
// } else {
// n := port.FlattenPath()[0:2]
// if strings.Join(n, "|") != strings.Join(node, "|") {
// return validator.NewValidateResult(false, fmt.Sprintf("%s is not same node with %s", port.FlattenName(), strings.Join(node, "|")))
// }
// }
// }
//
// return validator.NewValidateResult(true, "")
// }
