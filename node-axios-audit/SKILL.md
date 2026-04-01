---
name: node-audit
description: Scan node_modules for known malicious npm packages (e.g., plain-crypto-js from axios supply chain attack). Use when users want to audit their Node.js projects for security vulnerabilities or after hearing about npm supply chain attacks.
---

# Node.js Malicious Package Auditor

扫描 Node.js 项目中的已知恶意包，特别是供应链攻击相关的恶意依赖。

## 已知恶意包列表

以下是需要检测的已知恶意包（会根据最新安全情报更新）：

| 包名 | 攻击类型 | 发现时间 | 影响范围 |
|------|----------|----------|----------|
| `plain-crypto-js` | 供应链攻击（通过 axios 间接导入） | 2026-03 | 使用 axios 的项目 |
| `crypto-js-n` | 恶意克隆包 | 2026-03 | 搜索 crypto-js 的用户 |
| `ua-parser-js-latest` | 恶意克隆包 | 2024-02 | 误安装的用戶 |
| `colors-utils` | 恶意克隆包 | 2024-02 | 误安装的用戶 |

## 输入要求

在执行扫描前，确认以下信息：

- **扫描路径**：要扫描的项目根目录（默认为当前工作目录）
- **扫描深度**：是否扫描所有嵌套的 node_modules（默认扫描）

## 工作流程

### 步骤 1：定位 node_modules 目录

使用 `Glob` 或 `Bash` 工具找到所有 node_modules 目录：

```bash
# 方法 1：查找当前项目下的所有 node_modules
find . -type d -name "node_modules" 2>/dev/null

# 方法 2：只查找顶层 node_modules
ls -la node_modules 2>/dev/null
```

### 步骤 2：检查恶意包

在每个 node_modules 目录中检查是否存在恶意包：

```bash
# 检查 plain-crypto-js
if [ -d "node_modules/plain-crypto-js" ]; then
    echo "⚠️  发现恶意包：plain-crypto-js"
fi

# 检查其他恶意包
MALICIOUS_PACKAGES="plain-crypto-js crypto-js-n ua-parser-js-latest colors-utils"
for pkg in $MALICIOUS_PACKAGES; do
    if [ -d "node_modules/$pkg" ]; then
        echo "⚠️  发现恶意包：$pkg"
    fi
done
```

### 步骤 3：分析依赖来源

如果发现恶意包，分析它是如何被引入的：

```bash
# 查看 package.json 中是否有直接依赖
grep -r "plain-crypto-js" package.json package-lock.json yarn.lock 2>/dev/null

# 查看 npm ls 依赖树
npm ls plain-crypto-js 2>/dev/null || true
```

### 步骤 4：生成报告

根据扫描结果生成报告。**报告应输出到当前工作目录的显眼位置**，例如：
- `./node-audit-report.md`
- `./security-scan-result.md`

不要输出到 `.aipy` 或临时目录，确保用户能直接找到报告。

**无恶意包**：
```markdown
# Node.js 恶意包扫描报告

**扫描时间**: 2026-04-01
**扫描路径**: /path/to/project

## 结果

✅ **未发现已知恶意包**

### 扫描统计
- 检查的 node_modules 目录数：2
- 检测的恶意包数量：4
- 扫描状态：完成

### 检测的恶意包清单
- plain-crypto-js
- crypto-js-n
- ua-parser-js-latest
- colors-utils
```

**发现恶意包**：
```markdown
# ⚠️ Node.js 恶意包扫描报告

**扫描时间**: 2026-04-01
**扫描路径**: /path/to/project

## 🚨 发现恶意包!

| 包名 | 风险等级 | 位置 |
|------|----------|------|
| plain-crypto-js | CRITICAL | node_modules/plain-crypto-js |

## 攻击详情

- **包名**: plain-crypto-js
- **攻击类型**: 供应链攻击（通过 axios 间接导入）
- **风险等级**: CRITICAL
- **C2 服务器**: sfrclak.com
- **潜在危害**:
  - 窃取环境变量（AWS 密钥、API Key、数据库凭证）
  - 窃取 SSH 私钥
  - 窃取云服务凭证
  - 下载并执行第二阶段载荷（RAT 远程访问木马）

## 立即行动

### 第一阶段：隔离与止损（立即执行）
1. 断开网络连接（物理断网或禁用网卡）
2. 在 hosts 文件中阻止 C2 域名：`127.0.0.1 sfrclak.com`

### 第二阶段：排查持久化项
- macOS: 检查 `~/Library/LaunchAgents/` 下的可疑 .plist 文件
- Windows: 检查注册表启动项和计划任务

### 第三阶段：凭证重置
假设所有敏感信息已泄露，必须重置：
- [ ] API Tokens（AWS、数据库、Stripe 等）
- [ ] SSH Keys
- [ ] Git 凭证
- [ ] Web 会话（GitHub、npm、云服务平台）

详细修复步骤见 skill 文档。
```

### 步骤 5：修复指导（按严重程度分级）

#### 级别 1：仅发现恶意包（尚未执行 postinstall）

```bash
# 1. 删除恶意包
rm -rf node_modules/plain-crypto-js

# 2. 清理 npm 缓存
npm cache clean --force

# 3. 清理并重新安装依赖
rm -rf node_modules package-lock.json
npm install

# 4. 更新 axios 到安全版本
npm update axios
```

#### 级别 2：恶意包已执行（postinstall hook 已运行）

**第一阶段：隔离与止损**

```bash
# 1. 断开网络连接（物理断网或禁用网卡）
# macOS:
networksetup -setnetworkserviceenabled Wi-Fi off
networksetup -setnetworkserviceenabled Ethernet off

# Windows (PowerShell):
Disable-NetAdapter -Name "*" -Confirm:$false

# 2. 阻止 C2 域名（添加到 hosts 文件）
# Linux/macOS: /etc/hosts, Windows: C:\Windows\System32\drivers\etc\hosts
echo "127.0.0.1 sfrclak.com" | sudo tee -a /etc/hosts
```

**第二阶段：排查持久化项**

macOS 检查命令：
```bash
# 检查 LaunchAgents/Daemons
ls -la ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ | grep -E "(Update|NodeCheck|Plain)"

# 检查最近创建的 .plist 文件
find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons -name "*.plist" -mtime -7

# 检查 TCC 权限（全盘访问、辅助功能）
tccutil reset All  # 谨慎使用，会重置所有权限
```

Windows 检查命令：
```powershell
# 检查注册表启动项
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run

# 检查计划任务
Get-ScheduledTask | Where-Object {$_.TaskName -like "*Update*" -or $_.TaskName -like "*NodeCheck*"}

# 检查可疑文件
Get-ChildItem $env:PROGRAMDATA -Recurse -Filter "wt.exe" -ErrorAction SilentlyContinue
```

**第三阶段：凭证清理**

```bash
# 1. 检查并清理可能泄露的凭证文件
# 检查 .env 文件
find . -name ".env" -o -name "*.env" 2>/dev/null

# 检查 SSH 密钥
ls -la ~/.ssh/

# 2. 检查 npm 凭证
cat ~/.npmrc 2>/dev/null

# 3. 检查 AWS 凭证
cat ~/.aws/credentials 2>/dev/null
```

#### 级别 3：凭证重置清单

假设所有敏感信息已泄露，必须重置：

| 凭证类型 | 操作 |
|----------|------|
| API Tokens | 重置 AWS 密钥、数据库连接字符串、Stripe Key 等 |
| SSH Keys | 生成新密钥对，更新 GitHub/GitLab 部署密钥 |
| Git 凭证 | 更新保存的 Git 凭据 |
| Web 会话 | 在 GitHub、npm、云服务平台注销所有设备 |
| 数据库密码 | 重置所有数据库连接密码 |

## 快速扫描命令

使用 `Bash` 工具执行一键扫描：

```bash
#!/bin/bash
# node-audit-scan.sh

MALICIOUS_PACKAGES=(
    "plain-crypto-js"
    "crypto-js-n"
    "ua-parser-js-latest"
    "colors-utils"
)

FOUND_COUNT=0

echo "🔍 Node.js 恶意包扫描"
echo "扫描路径：$(pwd)"
echo "---"

for pkg in "${MALICIOUS_PACKAGES[@]}"; do
    # 在当前目录的 node_modules 中查找
    if [ -d "node_modules/$pkg" ]; then
        echo "⚠️  发现恶意包：$pkg"
        echo "   位置：$(pwd)/node_modules/$pkg"
        ((FOUND_COUNT++))
    fi
    
    # 递归查找所有 node_modules
    while IFS= read -r nm_dir; do
        if [ -d "$nm_dir/$pkg" ]; then
            echo "⚠️  发现恶意包：$pkg"
            echo "   位置：$nm_dir/$pkg"
            ((FOUND_COUNT++))
        fi
    done < <(find . -type d -name "node_modules" 2>/dev/null | grep -v "^./node_modules$")
done

echo "---"
if [ $FOUND_COUNT -eq 0 ]; then
    echo "✅ 未发现已知恶意包"
    exit 0
else
    echo "❌ 发现 $FOUND_COUNT 个恶意包，请立即处理"
    exit 1
fi
```

## 常见错误

### "node_modules 目录不存在"
- 确认当前目录是 Node.js 项目根目录
- 先运行 `npm install` 安装依赖

### "npm 命令未找到"
- 确认已安装 Node.js 和 npm
- 检查 PATH 环境变量

### 扫描结果为空但项目有依赖
- 检查是否在正确的目录下执行
- 确认 node_modules 不是符号链接

## 与其他技能配合

- **tool-writer**：如果需要创建更复杂的扫描工具，可以使用 tool-writer skill 生成
- **survey**：在扫描前使用 survey 收集用户的扫描需求
- **bash**：本技能依赖 Bash 工具执行扫描命令

## 参考资料

- [npm 安全公告](https://www.npmjs.com/advisories)
- [Snyk 漏洞数据库](https://snyk.io/vuln)
- [GitHub Security Advisories](https://github.com/advisories)

## 更新恶意包列表

当发现新的恶意包时，更新本技能文档中的"已知恶意包列表"部分，确保扫描范围覆盖最新威胁。

可通过以下渠道获取最新恶意包信息：
1. npm 官方安全公告
2. GitHub Security Advisories
3. 安全研究团队的报告
4. 社区披露的供应链攻击事件
