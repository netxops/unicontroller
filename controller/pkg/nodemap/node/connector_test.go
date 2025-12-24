package node

// func TestNodeConnectorMarshalJSON(t *testing.T) {
// 	connector := &NodeConnector{
// 		Name:      "TestConnector",
// 		mode:      api.Mode(1),
// 		IPv4:      api.StringList{"192.168.1.1", "10.0.0.1"},
// 		IPv6:      api.StringList{"2001:db8::1"},
// 		Ports:     []string{},
// 		portList:  []*NodePort{},
// 		FhrpGroup: []*FhrpGroup{},
// 	}

// 	data, err := json.Marshal(connector)
// 	if err != nil {
// 		t.Fatalf("Failed to marshal NodeConnector: %v", err)
// 	}

// 	var result map[string]interface{}
// 	err = json.Unmarshal(data, &result)
// 	if err != nil {
// 		t.Fatalf("Failed to unmarshal JSON data: %v", err)
// 	}

// 	expectedFields := []string{"name", "mode", "ipv4", "ipv6", "portList", "fhrpGroup"}
// 	for _, field := range expectedFields {
// 		if _, ok := result[field]; !ok {
// 			t.Errorf("Expected field %s not found in JSON", field)
// 		}
// 	}

// 	if result["mode"] != float64(1) {
// 		t.Errorf("Expected mode to be 1, got %v", result["mode"])
// 	}
// }
