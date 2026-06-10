"""Plugin loading system for module discovery and management."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Any, Optional

from src.exceptions import PluginLoadError
from src.modules.base import BaseModule
from src.utils.logger import AuditLogger


class PluginLoader:
    """Discovers, loads, and manages audit modules."""

    def __init__(self, module_package: str = "src.modules") -> None:
        self.module_package = module_package
        self.logger = AuditLogger.get_instance()
        self._modules: dict[str, BaseModule] = {}
        self._module_classes: dict[str, type[BaseModule]] = {}

    def discover(self) -> dict[str, type[BaseModule]]:
        self._module_classes.clear()
        try:
            package = importlib.import_module(self.module_package)
            package_path = getattr(package, "__path__", [])

            for importer, modname, ispkg in pkgutil.iter_modules(package_path):
                if modname.startswith("_") or ispkg:
                    continue
                try:
                    module = importlib.import_module(f"{self.module_package}.{modname}")
                    self._find_module_classes(module)
                except Exception as e:
                    self.logger.warning(f"Failed to load module {modname}: {e}")

        except Exception as e:
            raise PluginLoadError(f"Failed to discover modules: {e}")

        return self._module_classes

    def _find_module_classes(self, module: Any) -> None:
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseModule)
                and obj is not BaseModule
                and hasattr(obj, "module_name")
            ):
                module_name = obj.module_name
                self._module_classes[module_name] = obj
                self.logger.debug(f"Discovered module: {module_name}")

    def load_module(self, module_name: str, *args, **kwargs) -> BaseModule:
        if module_name not in self._module_classes:
            raise PluginLoadError(f"Module not found: {module_name}")
        cls = self._module_classes[module_name]
        instance = cls(*args, **kwargs)
        self._modules[module_name] = instance
        return instance

    def get_module(self, module_name: str) -> Optional[BaseModule]:
        return self._modules.get(module_name)

    def get_all_modules(self) -> dict[str, BaseModule]:
        return dict(self._modules)

    def unload_module(self, module_name: str) -> None:
        self._modules.pop(module_name, None)

    def reload_all(self, *args, **kwargs) -> dict[str, BaseModule]:
        self._modules.clear()
        self.discover()
        for module_name in self._module_classes:
            self.load_module(module_name, *args, **kwargs)
        return self._modules
