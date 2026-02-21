import importlib
import inspect
import logging
import os
import pkgutil
from typing import Dict, Type

from .base import BasePlugin

class PluginLoader:
    def __init__(self, plugin_package: str = "src.plugins"):
        self.plugin_package = plugin_package
        self.plugins: Dict[str, Type[BasePlugin]] = {}

    def load_plugins(self):
        """
        Dynamically loads all plugins in the plugins directory.
        """
        # Handle running from tests or different cwd
        try:
            import src.plugins
            package = src.plugins
            prefix = package.__name__ + "."
        except ImportError:
            logging.error("Failed to import src.plugins. Ensure you are running from the correct directory.")
            return

        # Iterate through modules in the package
        for _, modname, ispkg in pkgutil.iter_modules(package.__path__, prefix):
            if ispkg:
                continue
            
            try:
                module = importlib.import_module(modname)
                # Find classes in the module that inherit from BasePlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                        # Instantiate to get the service name
                        try:
                            instance = obj()
                            service = instance.service_name.lower()
                            self.plugins[service] = instance
                            logging.debug(f"Loaded plugin '{name}' for service '{service}'")
                        except TypeError as e:
                            logging.warning(f"Failed to instantiate plugin {name}: {e}")
            except Exception as e:
                logging.error(f"Error loading plugin module {modname}: {e}")
                
        logging.info(f"Loaded {len(self.plugins)} plugins.")

    def get_plugin(self, service_name: str) -> BasePlugin:
        """
        Returns the plugin instance for a given service.
        """
        return self.plugins.get(service_name.lower())
