def test_register():
    from archinfo.arch import Register

    register = Register(
        name="MIPS",
        size=8,
        vex_offset=10,
        vex_name="xyz",
        subregisters=["a", "b"],
        alias_names=("r0"),
        general_purpose=True,
        floating_point=True,
        vector=True,
        argument=True,
        persistent=True,
        default_value=("a", "global"),
        linux_entry_value="argv",
        concretize_unique=True,
        concrete=True,
        artificial=True,
    )
    assert register.name == "MIPS"
    assert register.size == 8
    assert register.vex_offset == 10
    assert register.vex_name == "xyz"
    assert register.subregisters == ["a", "b"]
    assert register.alias_names == ("r0")
    assert register.general_purpose
    assert register.floating_point
    assert register.vector
    assert register.argument
    assert register.persistent
    assert register.default_value == ("a", "global")
    assert register.linux_entry_value == "argv"
    assert register.concretize_unique
    assert register.concrete
    assert register.artificial
