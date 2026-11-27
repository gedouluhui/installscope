# InstallScope

安装前分析多个 Python wheel 会不会写入同一个目标文件。压缩包里的路径不同，不代表安装后不会冲突。

```sh
python -m pip install .
installscope demo --output demo
```

打开 `demo/collision.html` 查看根路径与 `.data/purelib` 最终汇入同一文件的真实证据；`demo/clear.html` 是合法共享目录对照。工具仅依赖 Python 标准库，不安装、导入或执行被检查的包。

```sh
installscope audit a.whl b.whl --platform windows --json result.json --html result.html
```

默认目标路径是报告中明示的虚拟布局，不是读取本机环境得到的结果。可用 `--scheme` 指定五类目标根目录。Windows 模式是保守大小写策略，不冒充完整 Win32 文件系统模拟。

CLEAR=0 仅表示声明的 payload 写入集未发现冲突；CONFLICT=1；ERROR=2。不检查已有环境、安装器生成的入口包装器/pyc、依赖兼容、CVE 或恶意软件。RECORD 一致也不能证明包可信。`.pth` 导入行只记录位置和摘要，不执行、不一律判恶意。

异常输入会停止扫描，避免预算重置后继续消耗；未知 ZIP64 目录等格式明确拒绝。完整范围、限额和测试见[英文文档](README.md)。MIT，AI 辅助实现，尚无 PyPI 发行或真实用户采用声明。

## 快速开始与支持状态

### 问题
把本地 wheel 载荷映射到声明的安装方案，在安装前暴露跨包目标路径冲突。

### 安装
```sh
python -m pip install .
```

### 成功命令
```sh
installscope demo --output demo
```
预期：自生成的 clear 与 collision 对照均被正确分类；退出码 0。

### 故意失败命令
```sh
installscope audit demo/demo_a-1.0-py3-none-any.whl demo/demo_b-1.0-py3-none-any.whl --platform posix
```
预期：两个载荷声明同一目标路径，命令退出码 1。

### 证据与覆盖边界
证据包括真实 ZIP 损坏、重映射冲突、平台策略、合法命名空间、同字节归属、文件/目录前缀、不执行控制和仅使用自生成无害 wheel 的独立 pip oracle。CLEAR 只覆盖声明的载荷写入集合，不代表整体环境安全。

### 支持状态
版本 0.1.0 支持 Python 3.10+，仅使用标准库。不声称已发布到 PyPI 或获得广泛安全认证。维护为尽力而为，不提供 SLA。

### 限制
不检查已安装环境、生成的包装器、重写脚本、.pyc 文件、依赖解析、ABI 兼容性、任意安装器副作用或漏洞。CRC/RECORD 与 SHA-256 不能证明来源或不存在恶意代码。
