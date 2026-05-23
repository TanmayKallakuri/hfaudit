from __future__ import annotations


def pickle_loader_script(model_path: str) -> str:
    """Generate a Python script that loads a pickle file inside the sandbox."""
    safe_path = model_path.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "import pickle\n"
        "import sys\n"
        "try:\n"
        f'    with open("{safe_path}", "rb") as f:\n'
        "        pickle.load(f)\n"
        '    print("LOAD_SUCCESS")\n'
        "except Exception as e:\n"
        '    print(f"LOAD_ERROR: {e}", file=sys.stderr)\n'
        "    sys.exit(1)\n"
    )


def pytorch_loader_script(model_path: str) -> str:
    """Generate a Python script that loads a PyTorch checkpoint inside the sandbox."""
    safe_path = model_path.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "import sys\n"
        "try:\n"
        "    import torch\n"
        f'    torch.load("{safe_path}", map_location="cpu")\n'
        '    print("LOAD_SUCCESS")\n'
        "except Exception as e:\n"
        '    print(f"LOAD_ERROR: {e}", file=sys.stderr)\n'
        "    sys.exit(1)\n"
    )


def tensorflow_loader_script(model_path: str) -> str:
    """Generate a Python script that loads a TensorFlow SavedModel inside the sandbox."""
    safe_path = model_path.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "import sys\n"
        "try:\n"
        "    import tensorflow as tf\n"
        f'    tf.saved_model.load("{safe_path}")\n'
        '    print("LOAD_SUCCESS")\n'
        "except Exception as e:\n"
        '    print(f"LOAD_ERROR: {e}", file=sys.stderr)\n'
        "    sys.exit(1)\n"
    )


def keras_loader_script(model_path: str) -> str:
    """Generate a Python script that loads a Keras model inside the sandbox."""
    safe_path = model_path.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "import sys\n"
        "try:\n"
        "    from tensorflow import keras\n"
        f'    keras.models.load_model("{safe_path}")\n'
        '    print("LOAD_SUCCESS")\n'
        "except Exception as e:\n"
        '    print(f"LOAD_ERROR: {e}", file=sys.stderr)\n'
        "    sys.exit(1)\n"
    )
