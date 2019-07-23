def test_import_no_capstone():
    import sys
    sys.modules['keystone'] = None
    import archinfo
