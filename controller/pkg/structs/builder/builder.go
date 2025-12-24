package builder

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/utils/tools"
	clientv3 "go.etcd.io/etcd/client/v3"
	"gopkg.in/yaml.v2"
)

const DefaultSnmpTimeout = 5
const DefaultSSHTimeout = 10

type CollectItemBuilder struct {
	collectItem structs.CollectItem
	remoteInfo  *structs.L2DeviceRemoteInfo
	err         error
}

func GetConfigs(path, manufacturer string, platform string, version string) (*structs.ModeConfig, *structs.HubConfig, error) {
	// 获取 ModeConfig
	modeConfigPath := filepath.Join(path, "mode_configs", fmt.Sprintf("%s_%s_%s.yaml",
		strings.ToLower(manufacturer), strings.ToLower(platform), strings.ToLower(version)))
	modeConfigData, err := ioutil.ReadFile(modeConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read mode config file: %v", err)
	}

	var modeConfig structs.ModeConfig
	err = yaml.Unmarshal(modeConfigData, &modeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal mode config: %v", err)
	}

	// 获取 HubConfig
	hubConfigPath := filepath.Join(path, "hub_configs", "default_hub_config.yaml")
	hubConfigData, err := ioutil.ReadFile(hubConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read hub config file: %v", err)
	}

	var hubConfig structs.HubConfig
	err = yaml.Unmarshal(hubConfigData, &hubConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal hub config: %v", err)
	}

	return &modeConfig, &hubConfig, nil
}

// GetConfigsFromEtcd 从etcd获取配置
func GetConfigsFromEtcd(etcdEndpoints []string, platform string, version string) (*structs.ModeConfig, *structs.HubConfig, error) {
	// 创建etcd客户端
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   etcdEndpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create etcd client: %v", err)
	}
	defer cli.Close()

	// 获取 ModeConfig
	modeConfigKey := filepath.Join("/configs", "mode_configs", fmt.Sprintf("%s_%s.yaml",
		strings.ToLower(platform), strings.ToLower(version)))
	modeConfigData, err := getFromEtcd(cli, modeConfigKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get mode config from etcd: %v", err)
	}

	var modeConfig structs.ModeConfig
	err = yaml.Unmarshal(modeConfigData, &modeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal mode config: %v", err)
	}

	// 获取 HubConfig
	hubConfigKey := filepath.Join("/configs", "hub_configs", "default_hub_config.yaml")
	hubConfigData, err := getFromEtcd(cli, hubConfigKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get hub config from etcd: %v", err)
	}

	var hubConfig structs.HubConfig
	err = yaml.Unmarshal(hubConfigData, &hubConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal hub config: %v", err)
	}

	return &modeConfig, &hubConfig, nil
}

// getFromEtcd 从etcd获取指定key的值
func getFromEtcd(cli *clientv3.Client, key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := cli.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if len(resp.Kvs) == 0 {
		return nil, fmt.Errorf("key not found: %s", key)
	}

	return resp.Kvs[0].Value, nil
}

func NewCollectItemBuilder(remoteInfo *structs.L2DeviceRemoteInfo) *CollectItemBuilder {
	return &CollectItemBuilder{
		collectItem: structs.CollectItem{},
		remoteInfo:  remoteInfo,
	}
}

func (b *CollectItemBuilder) WithName(name string) *CollectItemBuilder {
	b.collectItem.Name = name
	return b
}

func (b *CollectItemBuilder) WithMethod(method structs.CollectMethod) *CollectItemBuilder {
	b.collectItem.Method = method
	return b
}

func (b *CollectItemBuilder) WithTarget(target string) *CollectItemBuilder {
	b.collectItem.Target = target
	return b
}

func (b *CollectItemBuilder) WithSnmpVersion(version string) *CollectItemBuilder {
	if b.collectItem.Options.SNMPOptions != nil {
		b.collectItem.Options.SNMPOptions.Version = version
	}

	return b
}

func (b *CollectItemBuilder) WithLoginTimeout(timeout int) *CollectItemBuilder {
	b.collectItem.LoginTimeout = timeout
	return b
}

func (b *CollectItemBuilder) WithNoOutputTimeout(timeout int) *CollectItemBuilder {
	b.collectItem.NoOutputTimeout = timeout
	return b
}

func (b *CollectItemBuilder) WithExpectedType(expectedType structs.ExpectedType) *CollectItemBuilder {
	b.collectItem.ExpectedType = expectedType
	return b
}

func (b *CollectItemBuilder) WithOptions() *CollectItemBuilder {
	if b.remoteInfo == nil {
		b.err = fmt.Errorf("remoteInfo is nil")
		return b
	}

	options := structs.CollectItemOptions{}

	switch b.collectItem.Method {
	case structs.SNMP:
		options.SNMPOptions = &structs.SNMPOptions{
			Version:   tools.ConditionalT(b.remoteInfo.Snmp.SnmpVersion != "", b.remoteInfo.Snmp.SnmpVersion, "2c"),
			Community: tools.ConditionalT(len(b.remoteInfo.Community) > 0, b.remoteInfo.Community[0], ""),
			Timeout:   tools.ConditionalT(b.remoteInfo.TimeOut != 0, b.remoteInfo.TimeOut, int(DefaultSnmpTimeout)),
			Retries:   tools.ConditionalT(b.remoteInfo.Meta.SNMPRetries != 0, b.remoteInfo.Meta.SNMPRetries, 1),
			Host:      b.remoteInfo.Ip,
			Port:      tools.ConditionalT(b.remoteInfo.Meta.SNMPPort != 0, b.remoteInfo.Meta.SNMPPort, 161),
		}
	case structs.SSH:
		options.SSHOptions = &structs.SSHOptions{
			Username:     b.remoteInfo.Username,
			Password:     b.remoteInfo.Password,
			PrivateKey:   b.remoteInfo.PrivateKey,
			Host:         b.remoteInfo.Ip,
			Port:         tools.ConditionalT(b.remoteInfo.Meta.SSHPort != 0, b.remoteInfo.Meta.SSHPort, 22),
			AuthPassword: b.remoteInfo.AuthPass,
			Timeout:      tools.ConditionalT(b.remoteInfo.TimeOut != 0, b.remoteInfo.TimeOut, int(DefaultSSHTimeout)),
			Mode:         structs.SSHNetworkDevice,
		}
	case structs.TELNET:
		options.TelnetOptions = &structs.TelnetOptions{
			Username:     b.remoteInfo.Username,
			Password:     b.remoteInfo.Password,
			Host:         b.remoteInfo.Ip,
			Port:         tools.ConditionalT(b.remoteInfo.Meta.SSHPort != 0, b.remoteInfo.Meta.TelnetPort, 23),
			AuthPassword: b.remoteInfo.AuthPass,
			Timeout:      tools.ConditionalT(b.remoteInfo.TimeOut != 0, b.remoteInfo.TimeOut, int(DefaultSSHTimeout)),
		}

	default:
		b.err = fmt.Errorf("unsupported method: %s", b.collectItem.Method)
		return b
	}

	b.collectItem.Options = options
	return b
}
func (b *CollectItemBuilder) WithConfigs(path string, version string) *CollectItemBuilder {
	var modeConfig *structs.ModeConfig
	var hubConfig *structs.HubConfig

	if strings.HasPrefix(path, "etcd://") {
		// 从etcd获取配置
		etcdEndpoints := strings.Split(strings.TrimPrefix(path, "etcd://"), ",")
		modeConfig, hubConfig, b.err = GetConfigsFromEtcd(etcdEndpoints, b.remoteInfo.Platform, version)
	} else {
		// 从本地文件系统获取配置
		modeConfig, hubConfig, b.err = GetConfigs(path, b.remoteInfo.Manufacturer, b.remoteInfo.Platform, version)
	}

	if b.err == nil {
		b.collectItem.ModeConfig = *modeConfig
		b.collectItem.HubConfig = *hubConfig
	}

	return b
}

func (b *CollectItemBuilder) Build() (structs.CollectItem, error) {
	if b.err != nil {
		return structs.CollectItem{}, b.err
	}

	if b.collectItem.Name == "" {
		return structs.CollectItem{}, fmt.Errorf("collect item name is required")
	}
	if b.collectItem.Method == "" {
		return structs.CollectItem{}, fmt.Errorf("collect item method is required")
	}
	if b.collectItem.Target == "" {
		return structs.CollectItem{}, fmt.Errorf("collect item target is required")
	}

	return b.collectItem, nil
}
