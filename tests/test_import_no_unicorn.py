def test_import_no_capstone():
    import sys
    sys.modules['unicorn'] = None
    import archinfo
