def test_import_no_capstone():
    import sys
    sys.modules['pyvex'] = None
    import archinfo
