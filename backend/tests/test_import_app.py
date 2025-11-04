from importlib import import_module


def test_backend_module_importable():
    module = import_module('app.auth_mode')
    assert hasattr(module, 'AUTH_DEP')
