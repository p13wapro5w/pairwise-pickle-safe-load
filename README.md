# pairwise-pickle-safe-load

## 领域

安全

## 主题

反序列化白名单

## 说明

禁用 pickle、JSON schema 与递归类型校验。

初始状态下 `security/pickle_safe_load.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
