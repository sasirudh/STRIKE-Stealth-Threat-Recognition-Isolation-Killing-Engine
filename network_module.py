# network_module.py
# pip: pip install scikit-learn joblib psutil

import time, math, random, joblib
from collections import defaultdict, deque, Counter
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import psutil

MODEL_NET = "network_dt.joblib"

# sliding window per connection (for runtime; simplified)
flow_windows = defaultdict(lambda: deque())  # key -> deque of (ts, bytes, flags)

def extract_psutil_flows_snapshot():
    """Create simplified per-remote-IP features using psutil active connections.
       This is a runtime utility: returns a dict remote_ip -> features
    """
    now = time.time()
    conns = psutil.net_connections(kind='tcp')
    remote_map = {}
    for c in conns:
        if not c.raddr:
            continue
        rip = c.raddr.ip
        # naive counts per remote IP
        if rip not in remote_map:
            remote_map[rip] = {"pkts":0, "bytes":0, "syns":0}
        remote_map[rip]["pkts"] += 1
        # bytes approximated by local send/recv counters (not exact)
    # convert to feature list
    features = {}
    for rip, d in remote_map.items():
        # create features similar to KDD-ish: pkts, bytes(approx), pktrate (approx), service_count (0)
        features[rip] = np.array([d["pkts"], d["bytes"], d["syns"], 0.0])
    return features

# ---------- synthetic & training ----------
def gen_synthetic_network(n=3000):
    X = []
    y = []
    for _ in range(n):
        is_mal = random.random() < 0.2
        if not is_mal:
            pkts = abs(int(random.gauss(3,2)))
            b = abs(int(random.gauss(1200,800)))
            syns = abs(int(random.gauss(0.5,1)))
        else:
            # scanning/DoS-like: many packets, many SYNs or high bytes
            if random.random() < 0.5:
                pkts = abs(int(random.gauss(120,40)))
                b = abs(int(random.gauss(40000,20000)))
                syns = abs(int(random.gauss(40,20)))
            else:
                pkts = abs(int(random.gauss(30,15)))
                b = abs(int(random.gauss(8000,4000)))
                syns = abs(int(random.gauss(5,3)))
        feat = [pkts, b, syns, 0.0]
        X.append(feat)
        y.append(1 if is_mal else 0)
    return np.array(X), np.array(y)

def train_network_model():
    X,y = gen_synthetic_network()
    Xtr,Xte,ytr,yte = train_test_split(X,y,test_size=0.2,random_state=42,stratify=y)
    clf = DecisionTreeClassifier(max_depth=10, random_state=42)
    clf.fit(Xtr,ytr)
    yp = clf.predict(Xte)
    print("Network DT Classification Report")
    print(classification_report(yte, yp, digits=4))
    try:
        print("AUC:", roc_auc_score(yte, clf.predict_proba(Xte)[:,1]))
    except Exception:
        pass
    joblib.dump(clf, MODEL_NET)
    print("Saved network model to", MODEL_NET)

def network_score_from_features(feat_array):
    clf = joblib.load(MODEL_NET)
    prob = float(clf.predict_proba([feat_array])[0][1]) if hasattr(clf, "predict_proba") else float(clf.predict([feat_array])[0])
    return prob

if __name__ == "__main__":
    print("Training network model (synthetic flows)...")
    train_network_model()
