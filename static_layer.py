import os
import shutil
import time
from typing import Dict, List, Tuple
import lightgbm as lgb

# Import from your module
from static_module import (
    extract_ember_features,
    is_eicar_test_file,
    MODEL_PATH
)

class StaticLayer:
    def __init__(self):
        # 1. Re-initialize the history list
        self.scan_history = []
        
        # 2. Setup Quarantine Directory
        self.quarantine_dir = os.path.join(os.getcwd(), "quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # 3. Initialize EMBER Model
        self.use_ml = False
        self.model = None
        self._load_ember_model()
        
    def _load_ember_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model = lgb.Booster(model_file=MODEL_PATH)
                self.use_ml = True
                print("[Static Layer] Official EMBER model loaded.")
            except Exception as e:
                print(f"[Static Layer] Model load failed: {e}")

    def scan_file(self, file_path: str) -> Dict:
        result = {
            'score': 0.0,
            'label': 'Benign',
            'details': {
                'path': file_path,
                'method': 'Static_Analysis'
            }
        }

        # --- 1. EICAR Signature Detection ---
        if is_eicar_test_file(file_path):
            result['label'] = 'Malicious'
            result['score'] = 1.0
            result['details']['method'] = 'EICAR_Signature'
            self.scan_history.append(result)
            return result

        # --- 2. EMBER Static ML Detection ---
        if not self.use_ml:
            result['details']['error'] = "EMBER model not initialized"
            self.scan_history.append(result)
            return result

        features = extract_ember_features(file_path, debug=True)

        if features is None:
            result['label'] = 'Unknown'
            result['details']['error'] = 'Not a valid or supported PE file'
        else:
            score = self.model.predict([features])[0]
            result['score'] = round(float(score), 4)

            if score >= 0.85:
                result['label'] = 'Malicious'
            elif score >= 0.50:
                result['label'] = 'Suspicious'

            result['details']['method'] = 'EMBER_Static'
            result['details']['feature_count'] = len(features)

        self.scan_history.append(result)
        return result

    def get_scan_history(self, limit: int = 20) -> List[Dict]:
        """Returns the last N scan results."""
        return self.scan_history[-limit:]

    def quarantine_file(self, file_path: str) -> Tuple[bool, str]:
        """Moves a malicious file to the quarantine folder."""
        try:
            if not os.path.exists(file_path):
                return False, "File not found"
            
            filename = os.path.basename(file_path)
            # Add timestamp to prevent overwriting
            dest_name = f"{filename}_{int(time.time())}.bak"
            dest_path = os.path.join(self.quarantine_dir, dest_name)
            
            shutil.move(file_path, dest_path)
            return True, f"File quarantined to {dest_name}"
            
        except Exception as e:
            return False, f"Quarantine failed: {str(e)}"

    # --- ADDED: Missing Method to Fix Error ---
    def get_statistics(self) -> Dict:
        """
        Returns summary statistics for the dashboard.
        """
        total = len(self.scan_history)
        malicious = sum(1 for r in self.scan_history if r['label'] == 'Malicious')
        
        return {
            'total_scans': total,
            'malicious_detected': malicious,
            'model_active': self.use_ml
        }

    # --- ADDED: Placeholder for Training to prevent crashes ---
    def train_ml_model(self):
        """Static Layer uses pre-trained EMBER, so training is a no-op."""
        return True, "EMBER model is pre-trained. No re-training needed."