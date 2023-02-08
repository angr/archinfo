from mypy.nodes import TypeInfo
from mypy.plugin import Plugin, ClassDefContext


class ArchPluginPlugin(Plugin):
    def get_base_class_hook(self, fullname: str):
        if fullname == "archinfo.plugin.ArchPlugin":
            return arch_base_class_hook
        if fullname == "archinfo.plugin.RegisterPlugin":
            return register_base_class_hook
        return None


def arch_base_class_hook(ctx: ClassDefContext):
    ArchType = ctx.api.lookup_fully_qualified_or_none("archinfo.arch.Arch")
    assert isinstance(ArchType.node, TypeInfo)
    if ctx.cls.info not in ArchType.node.mro:
        ArchType.node.mro.insert(-1, ctx.cls.info)


def register_base_class_hook(ctx: ClassDefContext):
    RegType = ctx.api.lookup_fully_qualified_or_none("archinfo.arch.Register")
    assert isinstance(RegType.node, TypeInfo)
    if ctx.cls.info not in RegType.node.mro:
        RegType.node.mro.insert(-1, ctx.cls.info)


def plugin(_version: str):
    return ArchPluginPlugin
