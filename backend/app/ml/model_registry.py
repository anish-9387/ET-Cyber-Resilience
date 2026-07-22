import json
import os
import pickle
from typing import Dict, Any, Optional, Type
from datetime import datetime
from app.core.logger import logger
from app.core.config import settings


def _meta_path(model_path: str) -> str:
    return f"{model_path}.meta.json"


class ModelRegistry:
    def __init__(self, base_path: str = "models/"):
        self.base_path = base_path
        self._models: Dict[str, Any] = {}
        self._metadata: Dict[str, Dict[str, Any]] = {}
        os.makedirs(base_path, exist_ok=True)

    def register(self, name: str, model: Any, metadata: Optional[Dict[str, Any]] = None):
        self._models[name] = model
        self._metadata[name] = {
            "name": name,
            "type": type(model).__name__,
            "registered_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        }
        logger.info("Model '%s' registered in registry", name)

    def get(self, name: str) -> Optional[Any]:
        return self._models.get(name)

    def unregister(self, name: str):
        self._models.pop(name, None)
        self._metadata.pop(name, None)
        logger.info("Model '%s' unregistered from registry", name)

    def list_models(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._metadata)

    def save(self, name: str, path: Optional[str] = None):
        model = self._models.get(name)
        if model is None:
            raise KeyError(f"Model '{name}' not found in registry")
        save_path = path or os.path.join(self.base_path, f"{name}.pkl")
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "wb") as f:
            pickle.dump(model, f)
        self._metadata[name]["saved_at"] = datetime.utcnow().isoformat()
        self._metadata[name]["path"] = save_path
        with open(_meta_path(save_path), "w") as f:
            json.dump(self._metadata[name], f, indent=2, default=str)
        logger.info("Model '%s' saved to %s", name, save_path)

    def load(self, name: str, path: Optional[str] = None):
        load_path = path or os.path.join(self.base_path, f"{name}.pkl")
        if not os.path.exists(load_path):
            raise FileNotFoundError(f"Model file not found: {load_path}")
        with open(load_path, "rb") as f:
            model = pickle.load(f)
        self._models[name] = model
        meta_file = _meta_path(load_path)
        if os.path.exists(meta_file):
            with open(meta_file) as f:
                self._metadata[name] = json.load(f)
            self._metadata[name]["loaded_at"] = datetime.utcnow().isoformat()
        else:
            self._metadata[name] = {
                "name": name,
                "type": type(model).__name__,
                "loaded_at": datetime.utcnow().isoformat(),
                "path": load_path,
            }
        logger.info("Model '%s' loaded from %s", name, load_path)
        return model

    def save_all(self):
        for name in list(self._models.keys()):
            self.save(name)

    def load_all(self):
        if not os.path.exists(self.base_path):
            return
        for fname in os.listdir(self.base_path):
            if fname.endswith(".pkl"):
                name = fname[:-4]
                try:
                    self.load(name, os.path.join(self.base_path, fname))
                except Exception as e:
                    logger.error("Failed to load model '%s': %s", name, str(e))

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        return self._metadata.get(name)


model_registry = ModelRegistry(base_path=os.path.join(settings.BASE_DIR, "models") if hasattr(settings, "BASE_DIR") else "models/")
