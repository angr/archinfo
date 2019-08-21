def test_import_no_keystone():
    import sys
    sys.modules['keystone'] = None
    import archinfo
