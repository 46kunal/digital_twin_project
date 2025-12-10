# scanner/__init__.py
# Lazy proxy to avoid import-order / warning issues when running as module.
# Exposes run_scan at package level so `from scanner import run_scan` works.

def run_scan(*args, **kwargs):
    # import inside function so we avoid import-order cycles
    from .scanner import run_scan as _run_scan
    return _run_scan(*args, **kwargs)

__all__ = ["run_scan"]
