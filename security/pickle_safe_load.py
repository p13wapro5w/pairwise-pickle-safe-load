"""
security.pickle_safe_load
=========================

对外接口反序列化安全加固。

背景漏洞
--------
旧接口直接对客户端数据调用 ``pickle.loads``，仅在入口处做顶层类名白名单。
pickle 的 ``__reduce__`` 协议允许 **嵌套子对象** 返回 ``(可调用对象, 参数元组)``，
反序列化时解释器会直接执行该可调用对象，因此顶层白名单无法阻止 RCE::

    class Evil:
        def __reduce__(self):
            return (os.system, ("touch /tmp/pwned",))

    pickle.loads(pickle.dumps({"ok": [Whitelisted(), Evil()]}))  # 命令仍然执行

修复策略
--------
1. 彻底禁用 pickle 承接客户端数据（``disable_pickle`` / ``compat_path`` 默认拒绝）；
2. 对外只接受 JSON，并按显式 schema 校验（``json_schema`` / ``validation``）；
3. 递归类型白名单，只允许 JSON 标量与容器（``type_whitelist`` /
   ``recursive_validate``）——任何携带 ``__reduce__`` 的自定义对象根本无法进入
   数据结构，而不是靠黑名单去猜哪些类危险；
4. 限制嵌套深度与报文体积（``depth_limit`` / ``size_limit``），防止资源耗尽；
5. ``reduce_guard`` 提供纵深防御的 ``RestrictedUnpickler``，封禁 find_class 与
   REDUCE 指令，仅供内部可信数据的一次性迁移，永不承接客户端数据；
6. 未知字段策略、默认值填充、版本协商、稳定错误码映射、审计日志、规范化输出。
"""

from __future__ import annotations

import copy
import io
import json
import logging
import pickle
import sys
import unicodedata
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("security.pickle_safe_load")
logger.addHandler(logging.NullHandler())

# --- 硬性安全限值 ---------------------------------------------------------
MAX_DEPTH = 10
MAX_BYTES = 1 * 1024 * 1024  # 1 MiB
MAX_STR_LENGTH = 10_000
MAX_ITEMS = 10_000

# 只允许 JSON 能表达的类型；精确匹配 type()，自定义子类/自定义对象一律拒绝。
_ALLOWED_TYPES = (type(None), bool, int, float, str, list, dict)
_TYPE_NAMES = {
    type(None): "null",
    bool: "bool",
    int: "int",
    float: "float",
    str: "str",
    list: "array",
    dict: "object",
}

_KNOWN_SCHEMA_TYPES = {"object", "array", "int", "float", "bool", "str", "null"}

# 对外稳定错误码：不携带内部异常细节，避免信息泄漏。
ERROR_MESSAGES = {
    "PICKLE_DISABLED": "pickle is no longer accepted; send JSON instead",
    "REDUCE_BLOCKED": "pickle __reduce__ protocol is forbidden",
    "CLASS_LOOKUP_BLOCKED": "pickle global class lookup is forbidden",
    "SIZE_EXCEEDED": "payload exceeds maximum allowed size",
    "DEPTH_EXCEEDED": "payload nesting depth exceeds the limit",
    "TYPE_NOT_ALLOWED": "payload contains a value of a forbidden type",
    "UNKNOWN_FIELD": "payload contains an unknown field",
    "MISSING_FIELD": "required field is missing",
    "CONSTRAINT_VIOLATED": "value violates a schema constraint",
    "UNSUPPORTED_VERSION": "payload version is not supported",
    "MALFORMED_JSON": "payload is not valid JSON",
    "DUPLICATE_KEY": "payload contains duplicate object keys",
    "INVALID_PAYLOAD": "payload could not be validated",
}

_MISSING = object()


class SecurityError(Exception):
    """所有反序列化安全违规的统一异常，携带稳定错误码与字段路径。"""

    def __init__(self, code, message=None, path=None):
        super().__init__(message or ERROR_MESSAGES.get(code, code))
        self.code = code
        self.path = path


# --- 1. 禁用 pickle -------------------------------------------------------

def _banned_pickle_api(*_args, **_kwargs):
    raise SecurityError("PICKLE_DISABLED")


class pickles_disabled:
    """上下文管理器：在作用域内把 pickle.load/loads 替换为直接拒绝。

    进程级临时封禁，退出时恢复原状。默认安全入口 :func:`load_client_payload`
    本身从不调用 pickle，本机制用于测试与额外的进程级防护。
    """

    _TARGETS = (
        ("pickle", "load"),
        ("pickle", "loads"),
        ("_pickle", "load"),
        ("_pickle", "loads"),
    )

    def __enter__(self):
        self._originals = []
        for module_name, attr in self._TARGETS:
            module = sys.modules.get(module_name)
            if module is not None and hasattr(module, attr):
                self._originals.append((module, attr, getattr(module, attr)))
                setattr(module, attr, _banned_pickle_api)
        return self

    def __exit__(self, *_exc):
        for module, attr, original in reversed(self._originals):
            setattr(module, attr, original)
        return False


def disable_pickle(*_args, **_kwargs):
    """返回一个 pickle 封禁上下文：``with disable_pickle(): ...``。"""
    return pickles_disabled()


# --- 2. 类型白名单（递归校验的基础）---------------------------------------

def type_whitelist(value=_MISSING, extra=()):
    """返回当前允许的类型白名单；传入 value 时顺带判定该值是否合法。

    白名单只包含 JSON 原生类型，使用 ``type(x) in allowed`` 精确匹配，
    自定义类（以及任何定义了 ``__reduce__`` 的对象）都会被拒绝。
    """
    allowed = list(_ALLOWED_TYPES)
    if isinstance(extra, (tuple, list)):
        for candidate in extra:
            if isinstance(candidate, type) and candidate not in allowed:
                allowed.append(candidate)

    result = {
        "allowed_types": [
            _TYPE_NAMES.get(t, getattr(t, "__name__", str(t))) for t in allowed
        ],
        "value_type": None,
        "value_allowed": None,
    }
    if value is not _MISSING:
        result["value_type"] = _TYPE_NAMES.get(type(value), type(value).__name__)
        result["value_allowed"] = type(value) in tuple(allowed)
    return result


# --- 3. 深度限制 ----------------------------------------------------------

def _measure_depth(value):
    if isinstance(value, dict):
        return 1 + max((_measure_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_measure_depth(v) for v in value), default=0)
    return 0


def depth_limit(value=_MISSING, max_depth=MAX_DEPTH):
    """校验嵌套深度，返回实测深度报告；超限抛 ``DEPTH_EXCEEDED``。"""
    if value is _MISSING:
        return {"depth": 0, "max_depth": max_depth, "ok": True}
    depth = _measure_depth(value)
    if depth > max_depth:
        raise SecurityError("DEPTH_EXCEEDED", path="$")
    return {"depth": depth, "max_depth": max_depth, "ok": True}


# --- 4. 递归类型校验 ------------------------------------------------------

def recursive_validate(obj=_MISSING, _schema=None, *, max_depth=MAX_DEPTH):
    """递归遍历整棵数据树：

    - 每个节点类型必须在白名单内（精确 type 匹配，自定义对象无法蒙混）；
    - dict 的 key 必须是 str；
    - 可调用对象直接拒绝（``__reduce__`` 攻击载体进不来）；
    - 深度超过 ``max_depth`` 拒绝。
    """
    if obj is _MISSING:
        return {"ok": True, "depth": 0, "data": None, **type_whitelist()}

    def walk(node, depth, path):
        if depth > max_depth:
            raise SecurityError("DEPTH_EXCEEDED", path=path)
        if callable(node):
            raise SecurityError("TYPE_NOT_ALLOWED", "callable values are forbidden", path)
        if type(node) not in _ALLOWED_TYPES:
            raise SecurityError(
                "TYPE_NOT_ALLOWED",
                f"type {type(node).__name__!r} is not in the whitelist",
                path,
            )
        if isinstance(node, dict):
            for key, child in node.items():
                if type(key) is not str:
                    raise SecurityError("TYPE_NOT_ALLOWED", "object keys must be strings", path)
                walk(child, depth + 1, f"{path}.{key}")
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, depth + 1, f"{path}[{index}]")

    walk(obj, 0, "$")
    return {"ok": True, "depth": _measure_depth(obj), "data": obj}


# --- 5. 体积限制 ----------------------------------------------------------

def size_limit(raw=_MISSING, max_bytes=MAX_BYTES):
    """限制原始报文字节数，防止超大报文造成解析/内存压力。"""
    if raw is _MISSING:
        return {"size": 0, "max_bytes": max_bytes, "ok": True}
    size = len(raw) if isinstance(raw, (bytes, bytearray, str)) else 0
    if size > max_bytes:
        raise SecurityError("SIZE_EXCEEDED", f"payload size {size} > {max_bytes}")
    return {"size": size, "max_bytes": max_bytes, "ok": True}


# --- 6. reduce 守卫（纵深防御，仅用于内部可信迁移）------------------------

class RestrictedUnpickler(pickle.Unpickler):
    """封禁一切类查找与 REDUCE 指令的 unpickler。

    - find_class 一律抛错：GLOBAL/STACK_GLOBAL/INST/OBJ/NEWOBJ 全部依赖它，
      因此反序列化结果只能是内建容器与标量；
    - 显式覆写 load_reduce，哪怕未来 pickle 内部路径变化，REDUCE  opcode
      也会得到明确的 REDUCE_BLOCKED 而不是执行任意可调用对象。
    """

    def find_class(self, module, name):
        raise SecurityError(
            "CLASS_LOOKUP_BLOCKED", f"{module}.{name}", path=f"{module}.{name}"
        )

    def load_reduce(self):
        raise SecurityError("REDUCE_BLOCKED", path="$")


def guarded_loads(data):
    """仅用于内部可信数据迁移的反序列化入口，绝不接受客户端数据。"""
    if not isinstance(data, (bytes, bytearray)):
        raise SecurityError("TYPE_NOT_ALLOWED", "guarded_loads expects bytes")
    return RestrictedUnpickler(io.BytesIO(bytes(data))).load()


def reduce_guard(data=_MISSING, *_args):
    """返回守卫能力说明；传入 bytes 时走 RestrictedUnpickler 尝试解析。"""
    blocked = [
        "GLOBAL", "STACK_GLOBAL", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "REDUCE",
    ]
    if not isinstance(data, (bytes, bytearray)):
        return {
            "guarded": True,
            "find_class": "deny-all",
            "blocked_opcodes": blocked,
        }
    return guarded_loads(data)


# --- 7. JSON schema -------------------------------------------------------

DEFAULT_SCHEMA = {
    "type": "object",
    "additional_properties": False,
    "required": ["id"],
    "properties": {
        "version": {"type": "int", "default": 1, "allowed_versions": [1]},
        "id": {"type": "str", "max_length": 128},
        "payload": {
            "type": "object",
            "additional_properties": True,
            "properties": {},
        },
    },
}


def _check_schema(spec, path="$"):
    if not isinstance(spec, dict):
        raise SecurityError("CONSTRAINT_VIOLATED", "schema node must be an object", path)
    spec_type = spec.get("type")
    if spec_type not in _KNOWN_SCHEMA_TYPES:
        raise SecurityError(
            "CONSTRAINT_VIOLATED", f"unknown schema type {spec_type!r}", path
        )
    if spec_type == "object":
        properties = spec.get("properties", {})
        if not isinstance(properties, dict):
            raise SecurityError("CONSTRAINT_VIOLATED", "properties must be an object", path)
        for name, sub_spec in properties.items():
            _check_schema(sub_spec, f"{path}.{name}")
        for required in spec.get("required", []):
            if required not in properties:
                raise SecurityError(
                    "CONSTRAINT_VIOLATED",
                    f"required field {required!r} has no property spec",
                    path,
                )
    elif spec_type == "array" and "items" in spec:
        _check_schema(spec["items"], f"{path}[]")


def json_schema(spec=_MISSING, *_args, **_kwargs):
    """规范化一份 schema（非 dict 输入时返回内置默认 schema）。"""
    if not isinstance(spec, dict):
        return copy.deepcopy(DEFAULT_SCHEMA)
    _check_schema(spec)
    normalized = copy.deepcopy(spec)
    normalized.setdefault("additional_properties", False)
    return normalized


# --- 8. 未知字段 / 默认值 / 版本 ------------------------------------------

def unknown_field(data=_MISSING, schema=None, policy="reject"):
    """按 schema 处理未知字段：reject（默认）/ drop / keep。"""
    if not isinstance(data, dict) or not isinstance(schema, dict):
        return {"data": data, "unknown": [], "policy": policy}
    allowed = set(schema.get("properties", {}).keys())
    unknown = [key for key in data if key not in allowed]
    if unknown and policy == "reject":
        raise SecurityError(
            "UNKNOWN_FIELD", f"unknown fields: {unknown}", path=f"$.{unknown[0]}"
        )
    cleaned = data
    if unknown and policy == "drop":
        cleaned = {key: value for key, value in data.items() if key in allowed}
    return {"data": cleaned, "unknown": unknown, "policy": policy}


def default_value(data=_MISSING, schema=None):
    """为缺失的可选字段递归填充 schema 中声明的 default。"""
    if not isinstance(data, dict) or not isinstance(schema, dict):
        return data
    result = dict(data)
    for name, sub_spec in schema.get("properties", {}).items():
        if name not in result and isinstance(sub_spec, dict) and "default" in sub_spec:
            result[name] = copy.deepcopy(sub_spec["default"])
        elif (
            name in result
            and isinstance(result[name], dict)
            and isinstance(sub_spec, dict)
            and sub_spec.get("type") == "object"
        ):
            result[name] = default_value(result[name], sub_spec)
    return result


def version_field(payload=_MISSING, supported=None):
    """校验 payload 的 version 字段；缺省取首个受支持版本。"""
    if supported is None:
        supported = [1]
    elif not isinstance(supported, (list, tuple, set)):
        supported = [supported]
    if not isinstance(payload, dict):
        return {"version": supported[0], "supported": list(supported), "ok": True}
    version = payload.get("version", supported[0])
    if version not in supported:
        raise SecurityError(
            "UNSUPPORTED_VERSION", f"version {version!r} not in {supported}", "version"
        )
    return {"version": version, "supported": list(supported), "ok": True}


# --- 9. 错误码映射（不泄漏内部细节）---------------------------------------

def error_map(error=None, *_args):
    """把内部异常映射为对外稳定的错误码与通用文案。"""
    if isinstance(error, SecurityError):
        code, path = error.code, error.path
    elif isinstance(error, json.JSONDecodeError):
        code, path = "MALFORMED_JSON", None
    elif isinstance(error, RecursionError):
        code, path = "DEPTH_EXCEEDED", None
    else:
        code, path = "INVALID_PAYLOAD", None
    return {
        "code": code,
        "message": ERROR_MESSAGES.get(code, ERROR_MESSAGES["INVALID_PAYLOAD"]),
        "field": path,
    }


# --- 10. 审计日志 ---------------------------------------------------------

def audit(event=_MISSING, *_args, **fields):
    """输出结构化审计记录并返回该记录（只记录元数据，不落原始报文）。"""
    record = {
        "audit_id": uuid.uuid4().hex,
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "unspecified" if event is _MISSING else str(event),
        "fields": fields,
    }
    logger.warning("audit %s", json.dumps(record, sort_keys=True, default=str))
    return record


# --- 11. 规范化输出 -------------------------------------------------------

def canonicalize(data=_MISSING, schema=None):
    """生成规范化结果：NFC 字符串、对象键排序、默认值已填充、类型已收敛。"""
    if data is _MISSING:
        return None
    spec = schema if isinstance(schema, dict) else None

    def normalize(node, node_spec):
        if isinstance(node, str):
            text = unicodedata.normalize("NFC", node)
            if isinstance(node_spec, dict) and node_spec.get("strip"):
                text = text.strip()
            return text
        if isinstance(node, dict):
            if isinstance(node_spec, dict) and node_spec.get("type") == "object":
                node = default_value(node, node_spec)
            properties = node_spec.get("properties", {}) if node_spec else {}
            return {
                key: normalize(child, properties.get(key))
                for key, child in sorted(node.items())
            }
        if isinstance(node, list):
            item_spec = node_spec.get("items") if node_spec else None
            return [normalize(child, item_spec) for child in node]
        return node

    return normalize(data, spec)


# --- 12. schema 驱动的校验与完整加载管线 ----------------------------------

def _validate_against_schema(node, spec, path="$"):
    spec_type = spec.get("type")

    if spec_type == "object":
        if type(node) is not dict:
            raise SecurityError("TYPE_NOT_ALLOWED", "expected object", path)
        properties = spec.get("properties", {})
        for required in spec.get("required", []):
            if required not in node:
                raise SecurityError("MISSING_FIELD", path=f"{path}.{required}")
        for key, value in node.items():
            if key not in properties:
                if spec.get("additional_properties", False) is False:
                    raise SecurityError("UNKNOWN_FIELD", path=f"{path}.{key}")
                continue
            _validate_against_schema(value, properties[key], f"{path}.{key}")
    elif spec_type == "array":
        if type(node) is not list:
            raise SecurityError("TYPE_NOT_ALLOWED", "expected array", path)
        if len(node) > MAX_ITEMS:
            raise SecurityError("CONSTRAINT_VIOLATED", "array too long", path)
        item_spec = spec.get("items")
        if item_spec:
            for index, value in enumerate(node):
                _validate_against_schema(value, item_spec, f"{path}[{index}]")
    elif spec_type == "int":
        if type(node) is not int:  # 显式拒绝 bool 冒充 int
            raise SecurityError("TYPE_NOT_ALLOWED", "expected int", path)
    elif spec_type == "bool":
        if type(node) is not bool:
            raise SecurityError("TYPE_NOT_ALLOWED", "expected bool", path)
    elif spec_type == "float":
        if isinstance(node, bool) or not isinstance(node, (int, float)):
            raise SecurityError("TYPE_NOT_ALLOWED", "expected float", path)
    elif spec_type == "str":
        if type(node) is not str:
            raise SecurityError("TYPE_NOT_ALLOWED", "expected str", path)
        if len(node) > spec.get("max_length", MAX_STR_LENGTH):
            raise SecurityError("CONSTRAINT_VIOLATED", "string too long", path)
    elif spec_type == "null":
        if node is not None:
            raise SecurityError("TYPE_NOT_ALLOWED", "expected null", path)

    if "allowed_versions" in spec and node not in spec["allowed_versions"]:
        raise SecurityError("UNSUPPORTED_VERSION", path=path)
    if spec_type in ("int", "float"):
        if "min" in spec and node < spec["min"]:
            raise SecurityError("CONSTRAINT_VIOLATED", "below minimum", path)
        if "max" in spec and node > spec["max"]:
            raise SecurityError("CONSTRAINT_VIOLATED", "above maximum", path)


# pickle 流特征首字节：PROTO(0x80)、FRAME(0x95)，以及协议 0/1 文本 opcode。
_PICKLE_LEAD_BINARY = {0x80, 0x95}
_PICKLE_LEAD_TEXT = set(b"(c}]")


def _looks_like_pickle(raw):
    if not raw:
        return False
    head = raw.lstrip()[:1]
    if not head:
        return False
    return head[0] in _PICKLE_LEAD_BINARY or head[0] in _PICKLE_LEAD_TEXT


def _reject_json_constant(value):
    raise SecurityError("MALFORMED_JSON", f"forbidden JSON constant {value}")


def _reject_duplicate_keys(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise SecurityError("DUPLICATE_KEY", path=key)
        seen.add(key)
    return dict(pairs)


def _parse_json_payload(raw):
    if isinstance(raw, (bytes, bytearray)):
        raw_bytes = bytes(raw)
        if _looks_like_pickle(raw_bytes):
            raise SecurityError("PICKLE_DISABLED")
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise SecurityError("MALFORMED_JSON")
    elif isinstance(raw, str):
        text = raw
    else:
        # 已解析对象（内部调用）：仍会经过递归白名单与 schema 校验。
        return raw

    try:
        return json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except RecursionError:
        raise SecurityError("DEPTH_EXCEEDED")
    except json.JSONDecodeError:
        raise SecurityError("MALFORMED_JSON")


def load_client_payload(raw, schema=None, *, max_bytes=MAX_BYTES,
                        max_depth=MAX_DEPTH, client=None):
    """严格入口：完整的安全反序列化管线，违规则抛 :class:`SecurityError`。

    体积限制 -> 拒绝 pickle -> JSON 解析（拒 NaN/重复键）-> 递归白名单 +
    深度限制 -> schema 校验 -> 默认值 -> 规范化，全程审计。
    """
    try:
        size_limit(raw, max_bytes)
        obj = _parse_json_payload(raw)
        recursive_validate(obj, max_depth=max_depth)
        if isinstance(schema, dict):
            _validate_against_schema(obj, schema)
            if schema.get("type") == "object":
                obj = default_value(obj, schema)
        data = canonicalize(obj, schema if isinstance(schema, dict) else None)
        audit("payload_accepted", client=client, size=len(raw) if isinstance(
            raw, (bytes, bytearray, str)) else 0)
        return data
    except SecurityError as exc:
        audit(
            "payload_rejected",
            code=exc.code,
            path=exc.path,
            client=client,
        )
        raise


# 语义化别名：对外接口只应使用这个名字。
safe_load = load_client_payload


def validation(raw=_MISSING, schema=None, *, max_bytes=MAX_BYTES,
               max_depth=MAX_DEPTH, client=None):
    """信封式入口：不抛异常，返回 ``{"ok", "code", "message", "data"}``。"""
    try:
        data = load_client_payload(
            raw, schema, max_bytes=max_bytes, max_depth=max_depth, client=client
        )
        return {"ok": True, "code": None, "message": None, "data": data}
    except SecurityError as exc:
        return {"ok": False, "data": None, **error_map(exc)}


# --- 13. 旧客户端兼容路径 -------------------------------------------------

def compat_path(raw=_MISSING, schema=None, *, allow_trusted_migration=False,
                max_bytes=MAX_BYTES, max_depth=MAX_DEPTH, client=None):
    """旧客户端兼容入口。

    默认行为：识别到 pickle 报文直接拒绝（PICKLE_DISABLED），引导客户端迁移
    到 JSON。仅当显式 ``allow_trusted_migration=True``（内部可信数据一次性
    迁移）时，才走 :class:`RestrictedUnpickler`，且结果仍须通过递归白名单
    与 schema 校验。
    """
    try:
        if isinstance(raw, (bytes, bytearray)) and _looks_like_pickle(bytes(raw)):
            size_limit(raw, max_bytes)
            if not allow_trusted_migration:
                raise SecurityError("PICKLE_DISABLED")
            audit("pickle_trusted_migration", client=client)
            obj = guarded_loads(raw)
            recursive_validate(obj, max_depth=max_depth)
            if isinstance(schema, dict):
                _validate_against_schema(obj, schema)
                if schema.get("type") == "object":
                    obj = default_value(obj, schema)
            data = canonicalize(obj, schema if isinstance(schema, dict) else None)
            audit("payload_accepted", mode="trusted_migration", client=client)
            return {"ok": True, "code": None, "message": None, "data": data}

        data = load_client_payload(
            raw, schema, max_bytes=max_bytes, max_depth=max_depth, client=client
        )
        return {"ok": True, "code": None, "message": None, "data": data}
    except SecurityError as exc:
        # load_client_payload 内部已审计；这里只补齐 pickle 分支的拒绝审计。
        if isinstance(raw, (bytes, bytearray)) and _looks_like_pickle(bytes(raw)):
            audit("payload_rejected", code=exc.code, path=exc.path, client=client)
        return {"ok": False, "data": None, **error_map(exc)}


__all__ = [
    "SecurityError",
    "RestrictedUnpickler",
    "MAX_DEPTH",
    "MAX_BYTES",
    "ERROR_MESSAGES",
    "disable_pickle",
    "pickles_disabled",
    "json_schema",
    "type_whitelist",
    "depth_limit",
    "recursive_validate",
    "reduce_guard",
    "guarded_loads",
    "size_limit",
    "unknown_field",
    "default_value",
    "error_map",
    "version_field",
    "validation",
    "audit",
    "compat_path",
    "canonicalize",
    "load_client_payload",
    "safe_load",
]
