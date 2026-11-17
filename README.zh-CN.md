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
