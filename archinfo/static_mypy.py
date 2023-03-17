from typing import Optional
from importlib_metadata import entry_points

from mypy.nodes import TypeInfo, Decorator, ClassDef, NameExpr, FakeInfo
from mypy.types import Type, CallableType
from mypy.plugin import Plugin, ClassDefContext, AttributeContext
from mypy.checker import TypeChecker
from mypy import errorcodes


class ArchPluginPlugin(Plugin):
    # def get_base_class_hook(self, fullname: str):
    #    if fullname == "archinfo.plugin.ArchPlugin":
    #        return arch_base_class_hook
    #    if fullname == "archinfo.plugin.RegisterPlugin":
    #        return register_base_class_hook
    #    return None

    def get_attribute_hook(self, fullname):
        if fullname.startswith("archinfo.plugin.ArchPlugin."):
            return arch_attribute_hook
        return None

    def get_customize_class_mro_hook(self, fullname):
        return class_mro_hook

    def get_additional_deps(self, file):
        result = []
        if file.fullname in ("archinfo.arch", "archinfo.register"):
            result = [(10, entry.module, -1) for entry in entry_points(group="archinfo.plugins")]
        return result


def arch_attribute_hook(ctx: AttributeContext) -> Type:
    assert isinstance(ctx.api, TypeChecker)
    name: Optional[str] = getattr(ctx.context, "name", None)
    type2: Optional[TypeInfo] = getattr(ctx.type, "type", None)
    if type2 is None or name is None:
        return ctx.default_attr_type
    field = type2.get(name)
    if field is not None:
        return ctx.default_attr_type
    patched_name = type2.defn.keywords.get("patches", None)
    if patched_name is not None and hasattr(patched_name, "node") and isinstance(patched_name.node, TypeInfo):
        patched_field = patched_name.node.get(name)
        if patched_field is not None:
            if (
                isinstance(patched_field.node, Decorator)
                and patched_field.node.var.is_property
                and isinstance(patched_field.node.var.type, CallableType)
            ):
                return patched_field.node.var.type.ret_type
            return patched_field.type or ctx.default_attr_type
    ctx.api.fail(f'"Arch" (or plugin) has no member {name}', ctx.context, code=errorcodes.ATTR_DEFINED)
    return ctx.default_attr_type


def register_base_class_hook(ctx: ClassDefContext):
    RegType = ctx.api.lookup_fully_qualified("archinfo.arch.Register")
    assert isinstance(RegType.node, TypeInfo)
    if ctx.cls.info not in RegType.node.mro:
        RegType.node.mro.insert(-1, ctx.cls.info)


def class_mro_hook(ctx: ClassDefContext):
    if any(base.fullname == "archinfo.arch.Arch" for base in ctx.cls.info.mro):
        for entry_module in entry_points(group="archinfo.plugins"):
            module = ctx.api.modules[entry_module.module]
            for defn in module.defs:
                if (
                    isinstance(defn, ClassDef)
                    and "patches" in defn.keywords
                    and isinstance(defn.keywords["patches"], NameExpr)
                    and defn.keywords["patches"].name == ctx.cls.name
                ):
                    ctx.api.add_plugin_dependency(defn.fullname)
                    if isinstance(defn.info, FakeInfo):
                        ctx.api.defer()
                    elif defn.info not in ctx.cls.info.mro:
                        ctx.cls.info.mro.insert(-1, defn.info)
    elif ctx.cls.fullname == "archinfo.register.Register":
        for entry_module in entry_points(group="archinfo.plugins"):
            module = ctx.api.modules[entry_module.module]
            for defn in module.defs:
                if isinstance(defn, ClassDef) and any(
                    isinstance(base, NameExpr) and base.name == "RegisterPlugin" for base in defn.base_type_exprs
                ):
                    ctx.api.add_plugin_dependency(defn.fullname)
                    if isinstance(defn.info, FakeInfo):
                        ctx.api.defer()
                    elif defn.info not in ctx.cls.info.mro:
                        ctx.cls.info.mro.insert(-1, defn.info)


def plugin(_version: str):
    return ArchPluginPlugin
