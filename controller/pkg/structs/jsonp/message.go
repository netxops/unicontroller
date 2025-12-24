package jsonp

import (
	"encoding/json"
	"fmt"
)

const (
	InteractiveStatus   = uint16(1)
	InteractiveCmd      = uint16(100)
	InteractiveCmdAck   = uint16(102)
	InteractiveCmdReply = uint16(103)
)

type Message struct {
	Type uint16
	Raw  []byte
}

type interactiveStatus struct {
	Total  int
	Active int
}

type interactiveCmd struct {
	Id         string `json:"id"`
	Name       string `json:"name"`
	Command    string `json:"command"`
	Prompt     string `json:"prompt"`
	Pre_prompt string `json:"pre_prompt"`
	Timeout    int    `json:"timeout"`
	Close      bool   `json:"close"`
}

type interactiveCmdAck struct {
	Id    string
	Count int
}

type interactiveCmdReply struct {
	Id      string
	Success bool
	Msg     string
	Output  string
}

func NewMessage(tp uint16, rawMsg interface{}) (*Message, error) {
	bs, err := json.Marshal(rawMsg)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type: tp,
		Raw:  bs,
	}, nil
}

func (m *Message) decode() (interface{}, error) {
	switch m.Type {
	case InteractiveCmdAck:
		d := interactiveCmdAck{}
		err := json.Unmarshal(m.Raw, &d)
		return &d, err
	case InteractiveStatus:
		d := interactiveStatus{}
		err := json.Unmarshal(m.Raw, &d)
		return &d, err
	case InteractiveCmd:
		d := interactiveCmd{}
		err := json.Unmarshal(m.Raw, &d)
		return &d, err
	case InteractiveCmdReply:
		d := interactiveCmdReply{}
		err := json.Unmarshal(m.Raw, &d)
		return &d, err
	default:
		err := fmt.Errorf("unsupported message type %d", m.Type)
		return nil, err
	}
}

func NewInteractiveStatus(total, active int) (*interactiveStatus, uint16) {
	msg := interactiveStatus{
		Total:  total,
		Active: active,
	}
	return &msg, InteractiveStatus
}

func (m *Message) InteractiveStatus() (*interactiveStatus, error) {
	var d interface{}
	var err error
	if d, err = m.decode(); err != nil {
		return nil, err
	}

	msg, ok := d.(*interactiveStatus)
	if !ok {
		err = fmt.Errorf("message conversion failed. current message type is %d, expected type is %d", m.Type, InteractiveStatus)
	}
	return msg, err
}

func NewInteractiveCmd(id, name, command, prompt, pre_prompt string, timeout int, close bool) (*interactiveCmd, uint16) {
	return &interactiveCmd{
		Id:         id,
		Name:       name,
		Command:    command,
		Prompt:     prompt,
		Pre_prompt: pre_prompt,
		Timeout:    timeout,
		Close:      close,
	}, InteractiveCmd
}

func (m *Message) InteractiveCmd() (*interactiveCmd, error) {
	var d interface{}
	var err error
	if d, err = m.decode(); err != nil {
		return nil, err
	}

	msg, ok := d.(*interactiveCmd)
	if !ok {
		err = fmt.Errorf("message conversion failed. current message type is %d, expected type is %d", m.Type, InteractiveCmd)
	}
	return msg, err
}

func NewInteractiveCmdAck(id string, count int) (*interactiveCmdAck, uint16) {
	return &interactiveCmdAck{Id: id, Count: count}, InteractiveCmdAck
}

func (m *Message) InteractiveCmdAck() (*interactiveCmdAck, error) {
	var d interface{}
	var err error
	if d, err = m.decode(); err != nil {
		return nil, err
	}

	msg, ok := d.(*interactiveCmdAck)
	if !ok {
		err = fmt.Errorf("message conversion failed. current message type is %d, expected type is %d", m.Type, InteractiveCmdAck)
	}
	return msg, err

}

func NewInteractiveCmdReply(id string, success bool, msg, output string) (*interactiveCmdReply, uint16) {
	return &interactiveCmdReply{
		Id:      id,
		Success: success,
		Msg:     msg,
		Output:  output,
	}, InteractiveCmdReply
}

func (m *Message) InteractiveCmdReply() (*interactiveCmdReply, error) {
	var d interface{}
	var err error
	if d, err = m.decode(); err != nil {
		return nil, err
	}

	msg, ok := d.(*interactiveCmdReply)
	if !ok {
		err = fmt.Errorf("message conversion failed. current message type is %d, expected type is %d", m.Type, InteractiveCmdReply)
	}
	return msg, err
}
