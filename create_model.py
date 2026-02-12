# create_model.py
import lightgbm as lgb
import numpy as np
from static_module import MODEL_PATH

def create_dummy_model():
    print(f"Generating temporary model at: {MODEL_PATH}...")
    
    # EMBER uses 2381 features. We create fake data to train a lightweight model.
    # 100 samples, 2381 features
    X_train = np.random.rand(100, 2381) 
    # Random labels (0=Benign, 1=Malicious)
    y_train = np.random.randint(0, 2, 100)
    
    # Configure a fast, lightweight model
    params = {
        "boosting_type": "gbdt",
        "objective": "binary",
        "num_leaves": 31,
        "learning_rate": 0.05,
        "n_estimators": 10
    }
    
    # Train and save
    model = lgb.LGBMClassifier(**params)
    model.fit(X_train, y_train)
    model.booster_.save_model(MODEL_PATH)
    
    print("✓ Model created successfully!")
    print("  You can now run your main application.")

if __name__ == "__main__":
    create_dummy_model()