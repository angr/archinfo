def test_import_no_pyvex():
    import sys
    sys.modules['pyvex'] = None
    import archinfo
