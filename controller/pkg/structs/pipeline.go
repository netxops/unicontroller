package structs

// import (
// 	"encoding/json"
// 	"fmt"
// )
// type DataType string

// const (
//     TypeString           DataType = "string"
//     TypeInteger          DataType = "integer"
//     TypeFloat            DataType = "float"
//     TypeBoolean          DataType = "boolean"
//     TypeStringSlice      DataType = "[]string"
//     TypeMapStringString  DataType = "map[string]string"
//     TypeSliceMapString   DataType = "[]map[string]string"
//     TypeJSON             DataType = "json"
//     TypeSNMPList         DataType = "snmplist"
//     TypeSNMPSingle       DataType = "snmpsingle"
//     TypeTable            DataType = "table"
// )

// type FieldSchema struct {
// 	Name        string   `json:"name"`
// 	Type        DataType `json:"type"`
// 	Description string   `json:"description"`
// 	Required    bool     `json:"required"`
// }

// type ItemInterface interface {
// 	Process(input *PipelineData, config interface{}) error
// 	GetInputSchema() []FieldSchema
// 	GetOutputSchema() []FieldSchema
// }

// type StageInterface interface {
// 	AddItem(item ItemInterface) error
// 	GetItems() []ItemInterface
// 	Process(input *PipelineData, config interface{}) error
// 	GetInputSchema() []FieldSchema
// 	GetOutputSchema() []FieldSchema
// }

// type BaseStage struct {
// 	items []ItemInterface
// }

// func (s *BaseStage) AddItem(item ItemInterface) error {
// 	s.items = append(s.items, item)
// 	return nil
// }

// func (s *BaseStage) GetItems() []ItemInterface {
// 	return s.items
// }

// func (s *BaseStage) GetInputSchema() []FieldSchema {
// 	var schema []FieldSchema
// 	for _, item := range s.items {
// 		schema = append(schema, item.GetInputSchema()...)
// 	}
// 	return uniqueFieldSchema(schema)
// }

// func (s *BaseStage) GetOutputSchema() []FieldSchema {
// 	var schema []FieldSchema
// 	for _, item := range s.items {
// 		schema = append(schema, item.GetOutputSchema()...)
// 	}
// 	return uniqueFieldSchema(schema)
// }

// func uniqueFieldSchema(schema []FieldSchema) []FieldSchema {
// 	uniqueMap := make(map[string]FieldSchema)
// 	for _, field := range schema {
// 		uniqueMap[field.Name] = field
// 	}

// 	result := make([]FieldSchema, 0, len(uniqueMap))
// 	for _, field := range uniqueMap {
// 		result = append(result, field)
// 	}
// 	return result
// }

// type PipelineStage struct {
// 	Type  string         `json:"type"`
// 	Items []PipelineItem `json:"items"`
// }

// type PipelineItem struct {
// 	Type   string          `json:"type"`
// 	Config json.RawMessage `json:"config"`
// }

// type SNMPCollectItem struct{}

// func (i *SNMPCollectItem) Process(input *PipelineData, config interface{}) error {
// 	// 实现 SNMP 采集逻辑
// 	return nil
// }

// func (i *SNMPCollectItem) GetInputSchema() []FieldSchema {
// 	return []FieldSchema{
// 		{Name: "host", Type: TypeString, Description: "Target host", Required: true},
// 		{Name: "community", Type: TypeString, Description: "SNMP community", Required: true},
// 	}
// }

// func (i *SNMPCollectItem) GetOutputSchema() []FieldSchema {
// 	return []FieldSchema{
// 		{Name: "snmpData", Type: TypeSNMPList, Description: "Collected SNMP data", Required: true},
// 	}
// }

// func CreateStage(stageConfig PipelineStage) (StageInterface, error) {
// 	var stage StageInterface

// 	switch stageConfig.Type {
// 	case "Collect":
// 		stage = &CollectStage{}
// 	case "Parse":
// 		stage = &ParseStage{}
// 	// 其他 stage 类型...
// 	default:
// 		return nil, fmt.Errorf("unknown stage type: %s", stageConfig.Type)
// 	}

// 	for _, itemConfig := range stageConfig.Items {
// 		item, err := CreateItem(itemConfig)
// 		if err != nil {
// 			return nil, err
// 		}
// 		stage.AddItem(item)
// 	}

// 	return stage, nil
// }

// func CreateItem(itemConfig PipelineItem) (ItemInterface, error) {
// 	switch itemConfig.Type {
// 	case "SNMPCollect":
// 		return &SNMPCollectItem{}, nil
// 	// 其他 item 类型...
// 	default:
// 		return nil, fmt.Errorf("unknown item type: %s", itemConfig.Type)
// 	}
// }

// func ExecutePipeline(config PipelineConfig) (*PipelineData, error) {
// 	data := NewPipelineData()

// 	for _, stageConfig := range config.Stages {
// 		stage, err := CreateStage(stageConfig)
// 		if err != nil {
// 			return nil, err
// 		}

// 		err = stage.Process(data, nil) // 可能需要传递一些全局配置
// 		if err != nil {
// 			return nil, err
// 		}

// 		// 验证输出字段
// 		outputSchema := stage.GetOutputSchema()
// 		for _, field := range outputSchema {
// 			if _, exists := data.Get(field.Name); !exists && field.Required {
// 				return nil, fmt.Errorf("required output field %s not present after %s stage", field.Name, stageConfig.Type)
// 			}
// 		}
// 	}

// 	return data, nil
// }
