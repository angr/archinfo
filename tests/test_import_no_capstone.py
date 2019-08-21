def test_import_no_capstone():
    import sys
    sys.modules['capstone'] = None
    import archinfo
