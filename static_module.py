# static_module.py
import os
import joblib
import numpy as np
from resource_manager import get_resource_path

# ==============================================================================
# FULL NumPy legacy compatibility patch for EMBER + scikit-learn
# (Required for NumPy >= 1.24, Python 3.13)
# ==============================================================================

# Python aliases
if not hasattr(np, "int"):
    np.int = int
if not hasattr(np, "float"):
    np.float = float
if not hasattr(np, "bool"):
    np.bool = bool
if not hasattr(np, "str"):
    np.str = str
if not hasattr(np, "object"):
    np.object = object

# NumPy scalar aliases (CRITICAL)
if not hasattr(np, "str_"):
    np.str_ = str
if not hasattr(np, "object_"):
    np.object_ = object
if not hasattr(np, "unicode_"):
    np.unicode_ = str


import ember 
import lightgbm as lgb
import lief 

# ==============================================================================
# FINAL LIEF 0.9.x COMPATIBILITY PATCH FOR EMBER (Python 3.13 safe)
# ==============================================================================

import lief

# Determine modern LIEF error base
if hasattr(lief, 'lief_errors') and hasattr(lief.lief_errors, 'file_format_error'):
    NewLiefError = lief.lief_errors.file_format_error
else:
    NewLiefError = RuntimeError

# Legacy EMBER-expected exceptions
legacy_errors = [
    'bad_format',
    'bad_file',
    'pe_error',
    'parser_error',
    'read_out_of_bound'
]

for err in legacy_errors:
    if not hasattr(lief, err):
        setattr(lief, err, NewLiefError)


MODEL_PATH = get_resource_path("models/ember_model.txt")

def is_pe_file(file_path: str) -> bool:
    """
    Checks whether a file is a valid PE executable.
    """
    try:
        binary = lief.parse(file_path)
        return binary is not None
    except Exception:
        return False


def is_eicar_test_file(file_path: str) -> bool:
    """
    Detects the standard EICAR antivirus test string.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        return b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data
    except Exception:
        return False



def extract_ember_features(file_path, debug=False):
    """
    EMBER feature extraction with detailed debug logging.
    """
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()

        # --- Debug 1: File header ---
        if debug:
            print(f"[DEBUG] File size: {len(file_data)} bytes")
            print(f"[DEBUG] Header bytes: {file_data[:4]}")

        # Basic PE magic check
        if not file_data.startswith(b"MZ"):
            if debug:
                print("[DEBUG] Missing MZ header")
            return None

        # --- Debug 2: LIEF parsing ---
        try:
            binary = lief.parse(file_path)
            if debug:
                print("[DEBUG] LIEF parsing: SUCCESS")
                print(f"[DEBUG] PE machine: {getattr(binary.header, 'machine', 'UNKNOWN')}")
        except Exception as e:
            if debug:
                print(f"[DEBUG] LIEF parsing FAILED: {e}")

        # --- Debug 3: EMBER extraction ---
        extractor = ember.PEFeatureExtractor(feature_version=2)

        try:
            features = extractor.feature_vector(file_data)
            if debug:
                print("[DEBUG] EMBER feature vector generated")
        except Exception as e:
            if debug:
                print(f"[DEBUG] EMBER extractor FAILED: {e}")
            return None

        # --- Debug 4: Feature validation ---
        if features is None:
            if debug:
                print("[DEBUG] Features are None")
            return None

        if len(features) != 2381:
            if debug:
                print(f"[DEBUG] Feature length mismatch: {len(features)}")
            return None

        return np.array(features, dtype=np.float32)

    except Exception as e:
        if debug:
            print(f"[DEBUG] Fatal extraction error: {e}")
        return None



def train_static_model(X_train, y_train):
    """
    Trains a LightGBM model, which is the standard algorithm for EMBER.
    """
    params = {
        "boosting_type": "gbdt",
        "objective": "binary",
        "num_leaves": 31,
        "learning_rate": 0.05,
        "n_estimators": 100
    }
    
    model = lgb.LGBMClassifier(**params)
    model.fit(X_train, y_train)
    
    model.booster_.save_model(MODEL_PATH)
    print(f"EMBER model saved to {MODEL_PATH}")

def predict_sample(file_path):
    """Predicts malware probability for a single file."""
    features = extract_ember_features(file_path)
    if features is None:
        return None
    
    bst = lgb.Booster(model_file=MODEL_PATH)
    prob = bst.predict([features])[0]
    return float(prob)