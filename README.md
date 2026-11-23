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

## 漏洞成因

`pickle.loads` 执行子对象的 `__reduce__` 协议（`(可调用对象, 参数)`）时会直接拉起该可调用对象。
顶层类名白名单只检查根对象，嵌套在容器里的恶意对象照样触发 RCE：

```python
class Evil:
    def __reduce__(self):
        return (os.system, ("touch /tmp/pwned",))

pickle.loads(pickle.dumps({"ok": [Whitelisted(), Evil()]}))  # 命令执行
```

只要 pickle 解释器还在处理客户端数据，任何形式的类名/属性黑名单都无法保证安全。

## 修复方案（`security/pickle_safe_load.py`）

1. **彻底禁用 pickle 承接客户端数据**：`load_client_payload`（别名 `safe_load`）
   只解析 JSON；`disable_pickle()` 提供进程级封禁上下文；`compat_path` 识别到
   pickle 首字节（`0x80/0x95` 及协议 0 文本 opcode）直接返回 `PICKLE_DISABLED`。
2. **带 schema 的 JSON**：`json_schema` 规范化并自检 schema，`validation`
   信封式返回稳定错误码，不泄漏内部异常；支持类型、必填、长度、取值范围、版本约束。
3. **递归类型白名单**：`recursive_validate` + `type_whitelist` 精确匹配
   `None/bool/int/float/str/list/dict`，自定义对象与可调用对象在结构层即被拒绝，
   `__reduce__` 攻击载体根本无法进入数据树。
4. **深度与体积限制**：`depth_limit`（默认 10 层）、`size_limit`（默认 1 MiB），
   另限字符串长度、数组元素数量，拒绝 NaN/Infinity 与重复 JSON 键。
5. **纵深防御**：`reduce_guard` / `RestrictedUnpickler` 封禁 `find_class` 与
   REDUCE 指令，仅供 `compat_path(..., allow_trusted_migration=True)` 的内部
   可信数据一次性迁移使用，且结果仍须通过白名单与 schema 校验。
6. **配套能力**：未知字段策略（reject/drop/keep）、默认值填充、版本协商、
   结构化审计日志（只记元数据不落报文）、NFC + 键排序的规范化输出。

## 测试

- `tests/test_pickle_safe_load.py`：15 个入口的原始契约测试。
- `tests/test_exploit_chain.py`：真实 `__reduce__` RCE 攻击链验证——先证明裸
  `pickle.loads` 会执行命令，再验证各安全入口与 `RestrictedUnpickler` 全部阻断，
  以及深度、体积、类型、未知字段、NaN、重复键、bool 冒充 int 等防护。

