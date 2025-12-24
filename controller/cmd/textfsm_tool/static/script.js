// 加载示例数据
function loadExample() {
    document.getElementById('textfsm-template').value = `Value LOCAL_PORT (\\S+)
Value NEIGHBOR_INDEX (\\d+)
Value PEER_INTERFACE (\\S+)
Value SYSTEM_NAME (.+)
Value MANAGEMENT_IP ([\\d\\.]+)
Value CHASSIS_ID (\\S+)
Value SYSTEM_DESC (.+)

Start
  ^LLDP neighbor-information of port \\${NEIGHBOR_INDEX}\\[\\${LOCAL_PORT}\\]:
  ^  Neighbor index\\s+: \\${NEIGHBOR_INDEX}
  ^  Chassis ID\\s+: \\${CHASSIS_ID}
  ^  Port ID\\s+: \\${PEER_INTERFACE}
  ^  System name\\s+: \\${SYSTEM_NAME}
  ^  System description\\s+: \\${SYSTEM_DESC}
  ^  Management address\\s+: \\${MANAGEMENT_IP} -> Record`;

    document.getElementById('textfsm-input').value = `LLDP neighbor-information of port 1[Ethernet1/0/1]:
  Neighbor index   : 1
  Update time      : 0 days,0 hours,0 minutes,45 seconds
  Chassis type     : MAC address
  Chassis ID       : f063-f9d6-5970
  Port ID type     : Interface name
  Port ID          : GigabitEthernet0/0/24
  Port description : GigabitEthernet0/0/24
  System name        : HUAWEI
  System description : S5720-52X-LI-AC
Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.170 (S5720 V200R011C10SPC600)
Copyright (C) 2000-2018 HUAWEI TECH Co., Ltd.
  System capabilities supported : Bridge,Router
  System capabilities enabled   : Bridge,Router

  Management address type           : ipv4
  Management address                : 192.168.181.107
  Management address interface type : IfIndex
  Management address interface ID   : 57
  Management address OID            : 0`;
}

// 测试TextFSM
async function testTextFSM(event) {
    if (event) {
        event.preventDefault();
    }

    const form = document.getElementById('textfsm-form');
    const formData = new FormData(form);
    const template = formData.get('template');
    const input = formData.get('input');
    const resultDiv = document.getElementById('textfsm-result');
    const loadingDiv = document.getElementById('textfsm-loading');

    if (!template.trim() || !input.trim()) {
        showResult('textfsm-result', '请输入模板和测试数据', false);
        return;
    }

    loadingDiv.style.display = 'block';
    resultDiv.style.display = 'none';

    try {
        const response = await fetch('/api/textfsm', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                template: template,
                input: input
            })
        });

        const result = await response.json();
        loadingDiv.style.display = 'none';

        if (result.success) {
            let output = '解析成功！\n\n';
            if (result.fields && result.fields.length > 0) {
                output += '字段: ' + result.fields.join(', ') + '\n\n';
            }
            if (result.data && result.data.length > 0) {
                output += '解析结果:\n';
                result.data.forEach((item, index) => {
                    output += `记录 ${index + 1}:\n`;
                    for (const [key, value] of Object.entries(item)) {
                        output += `  ${key}: ${value}\n`;
                    }
                    output += '\n';
                });
            } else {
                output += '未找到匹配的记录';
            }
            showResult('textfsm-result', output, true);
        } else {
            showResult('textfsm-result', '错误: ' + result.error, false);
        }
    } catch (error) {
        loadingDiv.style.display = 'none';
        showResult('textfsm-result', '请求失败: ' + error.message, false);
    }
}

// 测试正则表达式
async function testRegex(event) {
    if (event) {
        event.preventDefault();
    }

    const form = document.getElementById('regex-form');
    const formData = new FormData(form);
    const pattern = formData.get('pattern');
    const input = formData.get('input');
    const resultDiv = document.getElementById('regex-result');
    const loadingDiv = document.getElementById('regex-loading');

    if (!pattern.trim() || !input.trim()) {
        showResult('regex-result', '请输入正则表达式和测试文本', false);
        return;
    }

    loadingDiv.style.display = 'block';
    resultDiv.style.display = 'none';

    try {
        const response = await fetch('/api/regex', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                pattern: pattern,
                input: input
            })
        });

        const result = await response.json();
        loadingDiv.style.display = 'none';

        if (result.success) {
            let output = '匹配成功！\n\n';
            if (result.matches && result.matches.length > 0) {
                output += '匹配结果:\n';
                result.matches.forEach((match, index) => {
                    output += `  ${index + 1}: ${match}\n`;
                });
            }
            if (result.groups && result.groups.length > 0) {
                output += '\n捕获组:\n';
                result.groups.forEach((group, index) => {
                    output += `  匹配 ${index + 1}:\n`;
                    group.forEach((g, gIndex) => {
                        output += `    组 ${gIndex}: ${g}\n`;
                    });
                });
            }
            if (result.matches.length === 0) {
                output += '未找到匹配项';
            }
            showResult('regex-result', output, true);
        } else {
            showResult('regex-result', '错误: ' + result.error, false);
        }
    } catch (error) {
        loadingDiv.style.display = 'none';
        showResult('regex-result', '请求失败: ' + error.message, false);
    }
}

// 显示结果
function showResult(elementId, message, isSuccess) {
    const resultDiv = document.getElementById(elementId);
    resultDiv.className = 'result ' + (isSuccess ? 'success' : 'error');
    resultDiv.innerHTML = '<pre>' + message + '</pre>';
    resultDiv.style.display = 'block';
}

// 清空所有内容
function clearAll() {
    document.getElementById('textfsm-template').value = '';
    document.getElementById('textfsm-input').value = '';
    document.getElementById('regex-pattern').value = '';
    document.getElementById('regex-input').value = '';
    document.getElementById('textfsm-result').style.display = 'none';
    document.getElementById('regex-result').style.display = 'none';
}

// 页面加载完成后加载示例
document.addEventListener('DOMContentLoaded', function () {
    loadExample();
});
