<p align="center">
  <a href="#简体中文">简体中文</a> &nbsp;|&nbsp;
  <a href="#繁體中文">繁體中文</a> &nbsp;|&nbsp;
  <a href="#english">English</a>
</p>

---

<h1 align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-orange.svg" alt="Version">
  <img src="https://img.shields.io/badge/Tests-98%20Passed-success.svg" alt="Tests">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg" alt="PRs Welcome">
</h1>

<h3 align="center">🔐 VaultKey — 轻量级终端密码生成与安全审计引擎</h3>

<p align="center">
  <b>一行命令生成高强度密码，终端内完成安全审计</b><br>
  <i>无需 GUI，无需联网，密码安全尽在指尖</i>
</p>

---

<a id="简体中文"></a>

## 🎉 项目介绍

VaultKey 是一款专为开发者、安全工程师和技术爱好者打造的**轻量级终端密码工具**。它将密码生成、强度分析、策略审计、熵值计算和泄露检测五大核心能力整合到一个优雅的 CLI 工具中。

### 为什么需要 VaultKey？

在日常开发和运维工作中，密码管理是一个绕不开的话题。你是否遇到过这些问题：

- 需要快速生成一组符合复杂策略的密码，却不想打开笨重的 GUI 工具？
- 想知道自己的密码到底有多安全，却找不到一个靠谱的终端分析工具？
- 需要批量审计团队密码是否符合 NIST、PCI-DSS 等安全标准？
- 担心密码已经在数据泄露中被公开，却不想把密码发送到第三方服务？

**VaultKey 就是为了解决这些问题而生的。**

### 自研差异化亮点

- 🔒 **完全离线运行**：密码泄露检测基于 SHA1 k-anonymity 模型本地计算，密码数据**绝不离开你的机器**
- 📐 **多维度熵分析**：同时计算 Shannon 熵、字符集熵和有效熵，从理论层面量化密码强度
- 🛡️ **企业级策略审计**：内置 NIST SP 800-63B、PCI-DSS、Strict 等策略模板，一键批量审计
- 🎨 **Rich 终端美化**：告别枯燥的纯文本输出，彩色表格、进度条、高亮提示让终端体验焕然一新
- ⚡ **零依赖安装**：核心功能仅依赖 Python 标准库 + Rich + Click，安装即用

---

## ✨ 核心特性

| 特性 | 说明 |
|------|------|
| 🎲 **随机密码生成** | 支持自定义长度、字符集，一键生成高强度随机密码 |
| 📝 **助记词密码** | 基于英文单词表生成易记但安全的助记词密码 |
| 🔢 **PIN 码生成** | 快速生成指定位数的纯数字 PIN 码 |
| 📦 **批量生成** | 支持一次生成多个密码，适合批量初始化场景 |
| 📊 **NIST 强度评分** | 基于 NIST SP 800-63B 标准的密码强度评估体系 |
| 🔍 **模式检测** | 自动识别键盘序列、重复字符、常见字典词等弱密码模式 |
| ⏱️ **暴力破解估算** | 根据密码复杂度估算暴力破解所需时间 |
| 🛡️ **多策略审计** | 内置 NIST / PCI-DSS / Strict / Custom 四种审计策略模板 |
| 📐 **三维度熵计算** | Shannon 熵、字符集熵、有效熵，全面量化密码信息量 |
| 🔎 **泄露检测** | 基于 SHA1 k-anonymity 模型的本地密码泄露检测 |
| 📄 **多格式导出** | 支持 JSON、CSV、TXT 三种报告格式 |
| ⚙️ **持久化配置** | 配置文件存储于 `~/.vaultkey/config.json`，跨会话保持 |

---

## 🚀 快速开始

### 环境要求

- **Python** >= 3.8
- **pip**（Python 包管理器）

### 安装

```bash
# 从 PyPI 安装（推荐）
pip install vaultkey

# 或从源码安装
git clone https://github.com/gitstq/VaultKey.git
cd VaultKey
pip install -e .
```

### 本地启动

安装完成后，直接在终端输入 `vaultkey` 即可使用：

```bash
# 查看帮助信息
vaultkey --help

# 生成一个 16 位随机密码
vaultkey generate

# 分析密码强度
vaultkey analyze "MyP@ssw0rd"
```

---

## 📖 详细使用指南

### 1. 密码生成

```bash
# 生成 16 位随机密码（默认）
vaultkey generate

# 指定长度为 20 位
vaultkey generate --length 20

# 生成助记词密码（如：correct-horse-battery-staple）
vaultkey generate --passphrase

# 生成 6 位 PIN 码
vaultkey generate --pin 6

# 批量生成 10 个密码
vaultkey generate --batch 10

# 组合使用：批量生成 5 个 24 位密码
vaultkey generate --length 24 --batch 5
```

### 2. 密码强度分析

```bash
# 分析单个密码
vaultkey analyze "MyP@ssw0rd"

# 从文件批量分析
vaultkey analyze --file passwords.txt

# 输出包含：NIST 评分、模式检测结果、暴力破解时间估算
```

### 3. 密码策略审计

```bash
# 使用默认策略审计密码
vaultkey audit "MyP@ssw0rd"

# 使用 NIST 策略批量审计
vaultkey audit --file passwords.txt --policy nist

# 使用 PCI-DSS 策略审计
vaultkey audit --file passwords.txt --policy pci-dss

# 使用严格策略审计
vaultkey audit --file passwords.txt --policy strict

# 查看所有可用策略
vaultkey config --list-policies
```

### 4. 密码泄露检测

```bash
# 检查单个密码是否已泄露
vaultkey check "MyP@ssw0rd"

# 从文件批量检测
vaultkey check --file passwords.txt
```

> 💡 **隐私说明**：泄露检测采用 k-anonymity 模型，仅发送密码 SHA1 哈希的前 5 位到远程 API，**你的完整密码永远不会被传输**。

### 5. 密码熵计算

```bash
# 计算密码熵值
vaultkey entropy "MyP@ssw0rd"

# 输出包含：Shannon 熵、字符集熵、有效熵
```

### 6. 报告导出

```bash
# 导出分析报告为 JSON
vaultkey export --type analysis --file passwords.txt --format json

# 导出审计报告为 CSV
vaultkey export --type audit --file passwords.txt --format csv --policy nist

# 导出为纯文本
vaultkey export --type analysis --file passwords.txt --format txt
```

### 7. 配置管理

```bash
# 查看当前配置
vaultkey config --show

# 列出所有可用策略
vaultkey config --list-policies
```

配置文件存储路径：`~/.vaultkey/config.json`

---

## 💡 设计思路与迭代规划

### 设计理念

VaultKey 的核心设计理念可以概括为三个关键词：**轻量、安全、专业**。

- **轻量**：不依赖沉重的 GUI 框架，不引入过多的第三方库，保持工具的精简和高效。一个 `pip install` 就能搞定一切。
- **安全**：密码处理全程在本地完成，泄露检测采用 k-anonymity 模型确保隐私安全。我们坚信，密码工具本身就必须是安全的。
- **专业**：评分体系基于 NIST SP 800-63B 标准，审计策略覆盖主流安全规范，熵计算采用学术界公认的方法论。

### 技术选型

| 技术选择 | 原因 |
|----------|------|
| **Python 3.8+** | 生态成熟、安全库丰富、跨平台兼容性好 |
| **Rich** | 终端美化的事实标准，表格/进度条/高亮一站搞定 |
| **Click** | Python CLI 框架中的佼佼者，API 优雅、文档完善 |
| **secrets** | Python 标准库，密码学安全的随机数生成器 |
| **hashlib** | Python 标准库，SHA1 哈希计算，用于泄露检测 |

### 后续迭代计划

- [ ] 🔐 **密码管理器集成**：支持与 1Password、Bitwarden 等主流密码管理器互通
- [ ] 🌐 **Web UI**：提供可选的浏览器界面，方便非技术用户使用
- [ ] 📱 **移动端适配**：通过 Termux 等工具支持移动端使用
- [ ] 🧪 **模糊测试模块**：对密码策略进行模糊测试，发现策略漏洞
- [ ] 📊 **团队报告**：生成团队级别的密码安全态势报告
- [ ] 🔄 **自动轮换**：集成密码自动轮换提醒功能

---

## 📦 安装与部署指南

### 方式一：pip 安装（推荐）

```bash
pip install vaultkey
```

### 方式二：从源码安装

```bash
# 克隆仓库
git clone https://github.com/gitstq/VaultKey.git
cd VaultKey

# 安装到当前环境
pip install -e .

# 或安装到用户目录（无需 root 权限）
pip install --user -e .
```

### 方式三：使用 pipx 安装（隔离环境）

```bash
pipx install vaultkey
```

### 配置说明

首次运行 VaultKey 时，会自动创建配置文件：

```
~/.vaultkey/
└── config.json
```

你可以通过以下命令查看和修改配置：

```bash
vaultkey config --show
```

---

## 🤝 贡献指南

我们欢迎并感谢每一位贡献者！无论是提交 Bug 报告、改进文档，还是贡献代码，都是对项目的宝贵支持。

### 提交 PR 的流程

1. **Fork** 本仓库到你的 GitHub 账号
2. **Clone** 你 fork 的仓库到本地
3. 创建一个**功能分支**：`git checkout -b feature/your-feature-name`
4. **开发**你的功能或修复
5. **测试**确保所有测试通过：`pytest`
6. **提交**代码：`git commit -m "feat: add your feature description"`
7. **推送**到你的 fork：`git push origin feature/your-feature-name`
8. 创建 **Pull Request**

### Commit 规范

我们采用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

| 类型 | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `docs` | 文档更新 |
| `style` | 代码格式调整（不影响逻辑） |
| `refactor` | 代码重构 |
| `test` | 测试相关 |
| `chore` | 构建/工具链相关 |

### Issue 反馈规则

- 使用清晰的标题描述问题
- 附上复现步骤和环境信息（Python 版本、操作系统等）
- 如有报错信息，请粘贴完整的错误堆栈

---

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。

```
MIT License

Copyright (c) 2024 gitstq

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/gitstq">gitstq</a> &nbsp;|&nbsp;
  ⭐ 如果觉得好用，欢迎 Star！
</p>

---
---

<a id="繁體中文"></a>

<h1 align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-orange.svg" alt="Version">
  <img src="https://img.shields.io/badge/Tests-98%20Passed-success.svg" alt="Tests">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg" alt="PRs Welcome">
</h1>

<h3 align="center">🔐 VaultKey — 輕量級終端密碼生成與安全審計引擎</h3>

<p align="center">
  <b>一行指令生成高強度密碼，終端內完成安全審計</b><br>
  <i>無需 GUI，無需連網，密碼安全盡在指尖</i>
</p>

---

## 🎉 專案介紹

VaultKey 是一款專為開發者、安全工程師和技術愛好者打造的**輕量級終端密碼工具**。它將密碼生成、強度分析、策略審計、熵值計算和洩漏偵測五大核心能力整合到一個優雅的 CLI 工具中。

### 為什麼需要 VaultKey？

在日常開發和維運工作中，密碼管理是一個繞不開的話題。你是否遇到過這些問題：

- 需要快速生成一組符合複雜策略的密碼，卻不想開啟笨重的 GUI 工具？
- 想知道自己的密碼到底有多安全，卻找不到一個可靠的終端分析工具？
- 需要批次審計團隊密碼是否符合 NIST、PCI-DSS 等安全標準？
- 擔心密碼已經在資料洩漏中被公開，卻不想把密碼傳送到第三方服務？

**VaultKey 就是為了解決這些問題而生的。**

### 自研差異化亮點

- 🔒 **完全離線運行**：密碼洩漏偵測基於 SHA1 k-anonymity 模型本地運算，密碼資料**絕不離開你的機器**
- 📐 **多維度熵分析**：同時計算 Shannon 熵、字元集熵和有效熵，從理論層面量化密碼強度
- 🛡️ **企業級策略審計**：內建 NIST SP 800-63B、PCI-DSS、Strict 等策略模板，一鍵批次審計
- 🎨 **Rich 終端美化**：告別枯燥的純文字輸出，彩色表格、進度條、高亮提示讓終端體驗煥然一新
- ⚡ **零依賴安裝**：核心功能僅依賴 Python 標準庫 + Rich + Click，安裝即用

---

## ✨ 核心特性

| 特性 | 說明 |
|------|------|
| 🎲 **隨機密碼生成** | 支援自訂長度、字元集，一鍵生成高強度隨機密碼 |
| 📝 **助記詞密碼** | 基於英文單詞表生成易記但安全的助記詞密碼 |
| 🔢 **PIN 碼生成** | 快速生成指定位數的純數字 PIN 碼 |
| 📦 **批次生成** | 支援一次生成多個密碼，適合批次初始化場景 |
| 📊 **NIST 強度評分** | 基於 NIST SP 800-63B 標準的密碼強度評估體系 |
| 🔍 **模式偵測** | 自動識別鍵盤序列、重複字元、常見字典詞等弱密碼模式 |
| ⏱️ **暴力破解估算** | 根據密碼複雜度估算暴力破解所需時間 |
| 🛡️ **多策略審計** | 內建 NIST / PCI-DSS / Strict / Custom 四種審計策略模板 |
| 📐 **三維度熵計算** | Shannon 熵、字元集熵、有效熵，全面量化密碼資訊量 |
| 🔎 **洩漏偵測** | 基於 SHA1 k-anonymity 模型的本地密碼洩漏偵測 |
| 📄 **多格式匯出** | 支援 JSON、CSV、TXT 三種報告格式 |
| ⚙️ **持久化設定** | 設定檔儲存於 `~/.vaultkey/config.json`，跨工作階段保持 |

---

## 🚀 快速開始

### 環境需求

- **Python** >= 3.8
- **pip**（Python 套件管理器）

### 安裝

```bash
# 從 PyPI 安裝（推薦）
pip install vaultkey

# 或從原始碼安裝
git clone https://github.com/gitstq/VaultKey.git
cd VaultKey
pip install -e .
```

### 本地啟動

安裝完成後，直接在終端輸入 `vaultkey` 即可使用：

```bash
# 查看說明資訊
vaultkey --help

# 生成一個 16 位隨機密碼
vaultkey generate

# 分析密碼強度
vaultkey analyze "MyP@ssw0rd"
```

---

## 📖 詳細使用指南

### 1. 密碼生成

```bash
# 生成 16 位隨機密碼（預設）
vaultkey generate

# 指定長度為 20 位
vaultkey generate --length 20

# 生成助記詞密碼（如：correct-horse-battery-staple）
vaultkey generate --passphrase

# 生成 6 位 PIN 碼
vaultkey generate --pin 6

# 批次生成 10 個密碼
vaultkey generate --batch 10

# 組合使用：批次生成 5 個 24 位密碼
vaultkey generate --length 24 --batch 5
```

### 2. 密碼強度分析

```bash
# 分析單個密碼
vaultkey analyze "MyP@ssw0rd"

# 從檔案批次分析
vaultkey analyze --file passwords.txt

# 輸出包含：NIST 評分、模式偵測結果、暴力破解時間估算
```

### 3. 密碼策略審計

```bash
# 使用預設策略審計密碼
vaultkey audit "MyP@ssw0rd"

# 使用 NIST 策略批次審計
vaultkey audit --file passwords.txt --policy nist

# 使用 PCI-DSS 策略審計
vaultkey audit --file passwords.txt --policy pci-dss

# 使用嚴格策略審計
vaultkey audit --file passwords.txt --policy strict

# 查看所有可用策略
vaultkey config --list-policies
```

### 4. 密碼洩漏偵測

```bash
# 檢查單個密碼是否已洩漏
vaultkey check "MyP@ssw0rd"

# 從檔案批次偵測
vaultkey check --file passwords.txt
```

> 💡 **隱私說明**：洩漏偵測採用 k-anonymity 模型，僅傳送密碼 SHA1 雜湊的前 5 位到遠端 API，**你的完整密碼永遠不會被傳輸**。

### 5. 密碼熵計算

```bash
# 計算密碼熵值
vaultkey entropy "MyP@ssw0rd"

# 輸出包含：Shannon 熵、字元集熵、有效熵
```

### 6. 報告匯出

```bash
# 匯出分析報告為 JSON
vaultkey export --type analysis --file passwords.txt --format json

# 匯出審計報告為 CSV
vaultkey export --type audit --file passwords.txt --format csv --policy nist

# 匯出為純文字
vaultkey export --type analysis --file passwords.txt --format txt
```

### 7. 設定管理

```bash
# 查看目前設定
vaultkey config --show

# 列出所有可用策略
vaultkey config --list-policies
```

設定檔儲存路徑：`~/.vaultkey/config.json`

---

## 💡 設計思路與迭代規劃

### 設計理念

VaultKey 的核心設計理念可以概括為三個關鍵詞：**輕量、安全、專業**。

- **輕量**：不依賴沉重的 GUI 框架，不引入過多的第三方函式庫，保持工具的精簡和高效。一個 `pip install` 就能搞定一切。
- **安全**：密碼處理全程在本地完成，洩漏偵測採用 k-anonymity 模型確保隱私安全。我們堅信，密碼工具本身就必須是安全的。
- **專業**：評分體系基於 NIST SP 800-63B 標準，審計策略覆蓋主流安全規範，熵計算採用學術界公認的方法論。

### 技術選型

| 技術選擇 | 原因 |
|----------|------|
| **Python 3.8+** | 生態成熟、安全庫豐富、跨平台相容性好 |
| **Rich** | 終端美化的事實標準，表格/進度條/高亮一站搞定 |
| **Click** | Python CLI 框架中的佼佼者，API 優雅、文件完善 |
| **secrets** | Python 標準庫，密碼學安全的亂數生成器 |
| **hashlib** | Python 標準庫，SHA1 雜湊運算，用於洩漏偵測 |

### 後續迭代計畫

- [ ] 🔐 **密碼管理器整合**：支援與 1Password、Bitwarden 等主流密碼管理器互通
- [ ] 🌐 **Web UI**：提供可選的瀏覽器介面，方便非技術使用者使用
- [ ] 📱 **行動端適配**：透過 Termux 等工具支援行動端使用
- [ ] 🧪 **模糊測試模組**：對密碼策略進行模糊測試，發現策略漏洞
- [ ] 📊 **團隊報告**：生成團隊級別的密碼安全態勢報告
- [ ] 🔄 **自動輪換**：整合密碼自動輪換提醒功能

---

## 📦 安裝與部署指南

### 方式一：pip 安裝（推薦）

```bash
pip install vaultkey
```

### 方式二：從原始碼安裝

```bash
# 複製仓库
git clone https://github.com/gitstq/VaultKey.git
cd VaultKey

# 安裝到目前環境
pip install -e .

# 或安裝到使用者目錄（無需 root 權限）
pip install --user -e .
```

### 方式三：使用 pipx 安裝（隔離環境）

```bash
pipx install vaultkey
```

### 設定說明

首次執行 VaultKey 時，會自動建立設定檔：

```
~/.vaultkey/
└── config.json
```

你可以透過以下指令查看和修改設定：

```bash
vaultkey config --show
```

---

## 🤝 貢獻指南

我們歡迎並感謝每一位貢獻者！無論是提交 Bug 回報、改進文件，還是貢獻程式碼，都是對專案的寶貴支持。

### 提交 PR 的流程

1. **Fork** 本倉庫到你的 GitHub 帳號
2. **Clone** 你 fork 的倉庫到本地
3. 建立一個**功能分支**：`git checkout -b feature/your-feature-name`
4. **開發**你的功能或修復
5. **測試**確保所有測試通過：`pytest`
6. **提交**程式碼：`git commit -m "feat: add your feature description"`
7. **推送**到你的 fork：`git push origin feature/your-feature-name`
8. 建立 **Pull Request**

### Commit 規範

我們採用 [Conventional Commits](https://www.conventionalcommits.org/) 規範：

| 類型 | 說明 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修復 |
| `docs` | 文件更新 |
| `style` | 程式碼格式調整（不影響邏輯） |
| `refactor` | 程式碼重構 |
| `test` | 測試相關 |
| `chore` | 建構/工具鏈相關 |

### Issue 回報規則

- 使用清晰的標題描述問題
- 附上重現步驟和環境資訊（Python 版本、作業系統等）
- 如有錯誤資訊，請貼上完整的錯誤堆疊

---

## 📄 開源協議

本專案基於 [MIT License](LICENSE) 開源。

```
MIT License

Copyright (c) 2024 gitstq

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/gitstq">gitstq</a> &nbsp;|&nbsp;
  ⭐ 如果覺得好用，歡迎 Star！
</p>

---
---

<a id="english"></a>

<h1 align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-orange.svg" alt="Version">
  <img src="https://img.shields.io/badge/Tests-98%20Passed-success.svg" alt="Tests">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg" alt="PRs Welcome">
</h1>

<h3 align="center">🔐 VaultKey — Lightweight Terminal Password Generator & Security Audit Engine</h3>

<p align="center">
  <b>Generate strong passwords and run security audits right from your terminal</b><br>
  <i>No GUI required. No internet needed. Password security at your fingertips.</i>
</p>

---

## 🎉 About VaultKey

VaultKey is a **lightweight terminal password toolkit** built for developers, security engineers, and tech enthusiasts. It brings together five core capabilities — password generation, strength analysis, policy auditing, entropy calculation, and breach detection — into one elegant CLI tool.

### Why VaultKey?

Password management is an unavoidable part of development and operations. Have you ever run into these situations?

- Need to quickly generate passwords that meet complex policies, but don't want to fire up a heavy GUI tool?
- Want to know how secure your passwords really are, but can't find a reliable terminal-based analyzer?
- Need to audit your team's passwords against standards like NIST or PCI-DSS in bulk?
- Worried your passwords might have been exposed in a data breach, but don't want to send them to a third-party service?

**VaultKey was built to solve exactly these problems.**

### What Sets Us Apart

- 🔒 **Fully Offline Capable** — Breach detection uses the SHA1 k-anonymity model for local computation. Your password data **never leaves your machine**.
- 📐 **Multi-Dimensional Entropy Analysis** — Calculates Shannon entropy, character-set entropy, and effective entropy simultaneously to quantify password strength from a theoretical standpoint.
- 🛡️ **Enterprise-Grade Policy Auditing** — Built-in templates for NIST SP 800-63B, PCI-DSS, Strict, and Custom policies. One-command bulk auditing.
- 🎨 **Beautiful Terminal Output** — Powered by Rich. Colorful tables, progress bars, and syntax highlighting bring your terminal experience to life.
- ⚡ **Minimal Dependencies** — Core features rely only on the Python standard library + Rich + Click. Install and go.

---

## ✨ Core Features

| Feature | Description |
|---------|-------------|
| 🎲 **Random Password Generation** | Customizable length and character sets. Generate strong random passwords with a single command. |
| 📝 **Passphrase Generation** | Creates memorable yet secure passphrases from an English wordlist. |
| 🔢 **PIN Generation** | Quickly generate numeric PINs of any length. |
| 📦 **Batch Generation** | Generate multiple passwords at once — ideal for bulk provisioning. |
| 📊 **NIST Strength Scoring** | Password strength assessment based on the NIST SP 800-63B standard. |
| 🔍 **Pattern Detection** | Automatically identifies keyboard sequences, repeated characters, dictionary words, and other weak patterns. |
| ⏱️ **Brute-Force Estimation** | Estimates the time required to brute-force a password based on its complexity. |
| 🛡️ **Multi-Policy Auditing** | Built-in audit templates: NIST / PCI-DSS / Strict / Custom. |
| 📐 **Triple Entropy Calculation** | Shannon entropy, character-set entropy, and effective entropy for a complete picture. |
| 🔎 **Breach Detection** | Local password breach detection using the SHA1 k-anonymity model. |
| 📄 **Multi-Format Export** | Export reports in JSON, CSV, or plain text. |
| ⚙️ **Persistent Configuration** | Settings stored in `~/.vaultkey/config.json`, preserved across sessions. |

---

## 🚀 Quick Start

### Prerequisites

- **Python** >= 3.8
- **pip** (Python package manager)

### Installation

```bash
# Install from PyPI (recommended)
pip install vaultkey

# Or install from source
git clone https://github.com/gitstq/VaultKey.git
cd VaultKey
pip install -e .
```

### Up and Running

Once installed, simply type `vaultkey` in your terminal:

```bash
# Show help
vaultkey --help

# Generate a 16-character random password
vaultkey generate

# Analyze password strength
vaultkey analyze "MyP@ssw0rd"
```

---

## 📖 Detailed Usage Guide

### 1. Password Generation

```bash
# Generate a 16-character random password (default)
vaultkey generate

# Specify a length of 20 characters
vaultkey generate --length 20

# Generate a passphrase (e.g., correct-horse-battery-staple)
vaultkey generate --passphrase

# Generate a 6-digit PIN
vaultkey generate --pin 6

# Batch generate 10 passwords
vaultkey generate --batch 10

# Combine options: batch generate 5 passwords, each 24 characters long
vaultkey generate --length 24 --batch 5
```

### 2. Password Strength Analysis

```bash
# Analyze a single password
vaultkey analyze "MyP@ssw0rd"

# Batch analyze from a file
vaultkey analyze --file passwords.txt

# Output includes: NIST score, pattern detection results, brute-force time estimate
```

### 3. Password Policy Auditing

```bash
# Audit with the default policy
vaultkey audit "MyP@ssw0rd"

# Bulk audit using the NIST policy
vaultkey audit --file passwords.txt --policy nist

# Audit using the PCI-DSS policy
vaultkey audit --file passwords.txt --policy pci-dss

# Audit using the Strict policy
vaultkey audit --file passwords.txt --policy strict

# List all available policies
vaultkey config --list-policies
```

### 4. Breach Detection

```bash
# Check if a single password has been breached
vaultkey check "MyP@ssw0rd"

# Batch check from a file
vaultkey check --file passwords.txt
```

> 💡 **Privacy Note**: Breach detection uses the k-anonymity model. Only the first 5 characters of your password's SHA1 hash are sent to the remote API. **Your full password is never transmitted.**

### 5. Entropy Calculation

```bash
# Calculate password entropy
vaultkey entropy "MyP@ssw0rd"

# Output includes: Shannon entropy, character-set entropy, effective entropy
```

### 6. Report Export

```bash
# Export analysis report as JSON
vaultkey export --type analysis --file passwords.txt --format json

# Export audit report as CSV
vaultkey export --type audit --file passwords.txt --format csv --policy nist

# Export as plain text
vaultkey export --type analysis --file passwords.txt --format txt
```

### 7. Configuration Management

```bash
# Show current configuration
vaultkey config --show

# List all available policies
vaultkey config --list-policies
```

Configuration file location: `~/.vaultkey/config.json`

---

## 💡 Design Philosophy & Roadmap

### Design Principles

VaultKey's core design philosophy can be summed up in three words: **Lightweight, Secure, Professional**.

- **Lightweight** — No heavy GUI frameworks, no excessive third-party libraries. Keep it lean and efficient. One `pip install` is all you need.
- **Secure** — All password processing happens locally. Breach detection uses the k-anonymity model to protect your privacy. We believe that a password tool must be secure by definition.
- **Professional** — Scoring is based on the NIST SP 800-63B standard. Audit policies cover mainstream security specifications. Entropy calculations follow academically recognized methodologies.

### Technology Choices

| Choice | Rationale |
|--------|-----------|
| **Python 3.8+** | Mature ecosystem, rich security libraries, excellent cross-platform compatibility |
| **Rich** | The de facto standard for terminal beautification — tables, progress bars, and highlighting in one package |
| **Click** | Among the best Python CLI frameworks — elegant API, excellent documentation |
| **secrets** | Python standard library — cryptographically secure random number generator |
| **hashlib** | Python standard library — SHA1 hashing for breach detection |

### Roadmap

- [ ] 🔐 **Password Manager Integration** — Interoperability with 1Password, Bitwarden, and other popular password managers
- [ ] 🌐 **Web UI** — An optional browser interface for non-technical users
- [ ] 📱 **Mobile Support** — Compatibility with Termux and similar mobile terminal tools
- [ ] 🧪 **Fuzz Testing Module** — Fuzz-test password policies to uncover edge cases and weaknesses
- [ ] 📊 **Team Reports** — Generate team-level password security posture reports
- [ ] 🔄 **Auto-Rotation Reminders** — Integrated password rotation alerts and scheduling

---

## 📦 Installation & Deployment

### Option 1: pip Install (Recommended)

```bash
pip install vaultkey
```

### Option 2: Install from Source

```bash
# Clone the repository
git clone https://github.com/gitstq/VaultKey.git
cd VaultKey

# Install into the current environment
pip install -e .

# Or install into the user directory (no root required)
pip install --user -e .
```

### Option 3: Install with pipx (Isolated Environment)

```bash
pipx install vaultkey
```

### Configuration

On first run, VaultKey automatically creates a configuration file:

```
~/.vaultkey/
└── config.json
```

View and modify your configuration with:

```bash
vaultkey config --show
```

---

## 🤝 Contributing

We welcome and appreciate every contributor! Whether it's filing a bug report, improving documentation, or contributing code — it all helps.

### How to Submit a PR

1. **Fork** this repository to your GitHub account
2. **Clone** your fork locally
3. Create a **feature branch**: `git checkout -b feature/your-feature-name`
4. **Develop** your feature or fix
5. **Test** — make sure all tests pass: `pytest`
6. **Commit** your changes: `git commit -m "feat: add your feature description"`
7. **Push** to your fork: `git push origin feature/your-feature-name`
8. Open a **Pull Request**

### Commit Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation update |
| `style` | Code formatting (no logic change) |
| `refactor` | Code refactoring |
| `test` | Test-related changes |
| `chore` | Build/tooling changes |

### Issue Reporting

- Use a clear, descriptive title
- Include reproduction steps and environment details (Python version, OS, etc.)
- Paste the full error stack trace when applicable

---

## 📄 License

This project is released under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2024 gitstq

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/gitstq">gitstq</a> &nbsp;|&nbsp;
  ⭐ If you find VaultKey useful, please give it a star!
</p>
