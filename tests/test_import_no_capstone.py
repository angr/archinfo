def test_import_no_capstone():
    import sys
    import archinfo
    sys.modules['capstone'] = None
