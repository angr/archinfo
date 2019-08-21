def test_import_no_unicorn():
    import sys
    sys.modules['unicorn'] = None
    import archinfo
