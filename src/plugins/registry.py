"""
Plugin registry with auto-discovery.

Discovers plugins from the plugins directory, validates them,
and manages their lifecycle.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path

from src.plugins.base import AnalysisContext, AnalyzerPlugin, BaseAnalyzerPlugin
from src.schemas.findings import Finding


class PluginRegistry:
    """
    Registry that manages plugin discovery, loading, and execution.

    Supports:
    - Auto-discovery from the plugins directory
    - Manual registration
    - Filtering by name
    - Ordered execution
    """

    def __init__(self) -> None:
        self._plugins: dict[str, AnalyzerPlugin] = {}
        self._load_order: list[str] = []

    @property
    def plugins(self) -> dict[str, AnalyzerPlugin]:
        return dict(self._plugins)

    @property
    def plugin_names(self) -> list[str]:
        return list(self._load_order)

    def register(self, plugin: AnalyzerPlugin) -> None:
        """Manually register a plugin instance."""
        name = plugin.name
        if name in self._plugins:
            raise ValueError(f"Plugin '{name}' is already registered")
        self._plugins[name] = plugin
        self._load_order.append(name)

        # Call setup hook if available
        if isinstance(plugin, BaseAnalyzerPlugin):
            plugin.setup()

    def unregister(self, name: str) -> None:
        """Remove a plugin by name."""
        if name in self._plugins:
            plugin = self._plugins[name]
            if isinstance(plugin, BaseAnalyzerPlugin):
                plugin.teardown()
            del self._plugins[name]
            self._load_order.remove(name)

    def get(self, name: str) -> AnalyzerPlugin | None:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def discover_plugins(self, package_path: str | None = None) -> int:
        """
        Auto-discover plugins from the plugins package.

        Scans all modules in the plugins directory for classes that
        implement the AnalyzerPlugin protocol.

        Returns the number of plugins discovered.
        """
        if package_path is None:
            package_path = str(Path(__file__).parent)

        count = 0
        package_name = "src.plugins"

        try:
            importlib.import_module(package_name)
        except ImportError:
            return 0

        for importer, module_name, is_pkg in pkgutil.iter_modules([package_path]):
            if module_name.startswith("_") or module_name in ("base", "registry"):
                continue

            try:
                module = importlib.import_module(f"{package_name}.{module_name}")
            except ImportError:
                continue

            for attr_name, attr in inspect.getmembers(module, inspect.isclass):
                if attr is BaseAnalyzerPlugin:
                    continue

                # Check if it's a proper plugin class
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseAnalyzerPlugin)
                    and hasattr(attr, "name")
                    and attr.name != "unnamed_plugin"
                ):
                    try:
                        instance = attr()
                        if instance.name not in self._plugins:
                            self.register(instance)
                            count += 1
                    except Exception:
                        continue

        return count

    def run_all(
        self,
        context: AnalysisContext,
        filter_names: list[str] | None = None,
    ) -> list[Finding]:
        """
        Run all registered plugins (or a filtered subset) on the given context.

        Returns aggregated findings from all plugins.
        """
        findings: list[Finding] = []
        # An empty list means "run no plugins"; only None means "run all".
        names_to_run = self._load_order if filter_names is None else filter_names

        for name in names_to_run:
            plugin = self._plugins.get(name)
            if plugin is None:
                continue

            # Check language support
            if isinstance(plugin, BaseAnalyzerPlugin):
                if not plugin.enabled:
                    continue
                if not plugin.supports_language(context.language):
                    continue

            try:
                plugin_findings = plugin.analyze(context)
                findings.extend(plugin_findings)
                # Update context with findings for cascading analysis
                context.prior_findings.extend(plugin_findings)
            except Exception as e:
                from src.schemas.findings import Category, Location, Severity
                findings.append(Finding(
                    rule_id="PLG-ERR",
                    title=f"Plugin '{name}' failed",
                    description=f"Plugin '{name}' raised an exception: {e}",
                    severity=Severity.INFO,
                    category=Category.MAINTAINABILITY,
                    location=Location(file_path=context.file_path, start_line=1),
                    source_analyzer=f"plugin:{name}",
                ))

        return findings

    def teardown_all(self) -> None:
        """Teardown all plugins."""
        for name in list(self._load_order):
            self.unregister(name)
