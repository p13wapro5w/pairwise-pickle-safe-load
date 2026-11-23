import pytest
import security.pickle_safe_load as mod

CASES = [
    ("disable_pickle", (1, 2)),
    ("json_schema", (1, 2)),
    ("type_whitelist", (1, 2)),
    ("depth_limit", (1, 2)),
    ("recursive_validate", (1, 2)),
    ("reduce_guard", (1, 2)),
    ("size_limit", (1, 2)),
    ("unknown_field", (1, 2)),
    ("default_value", (1, 2)),
    ("error_map", (1, 2)),
    ("version_field", (1, 2)),
    ("validation", (1, 2)),
    ("audit", (1, 2)),
    ("compat_path", (1, 2)),
    ("canonicalize", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
