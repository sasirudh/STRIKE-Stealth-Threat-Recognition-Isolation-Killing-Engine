# dynamic_module.py
import torch
import torch.nn as nn
import numpy as np
import joblib
import psutil

# --- 1. Define the exact architecture used in training ---
# This must match your notebook exactly for load_state_dict to work
class MalwareModel(nn.Module):
    def __init__(self, input_size, hidden_size=128, num_layers=2, dropout=0.3, model_type='GRU'):
        super(MalwareModel, self).__init__()
        self.model_type = model_type
        
        if model_type == 'LSTM':
            self.rnn = nn.LSTM(input_size, hidden_size, num_layers, 
                               batch_first=True, dropout=dropout if num_layers > 1 else 0)
        else:
            self.rnn = nn.GRU(input_size, hidden_size, num_layers, 
                              batch_first=True, dropout=dropout if num_layers > 1 else 0)
                              
        self.dropout = nn.Dropout(dropout)
        self.fc1 = nn.Linear(hidden_size, 64)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(64, 1)
        self.sigmoid = nn.Sigmoid()
    
    def forward(self, x):
        # Reshape for RNN: (batch, seq_len=1, features)
        x = x.unsqueeze(1)
        
        # Forward pass
        out, _ = self.rnn(x)
        
        # Take last time step
        out = out[:, -1, :]\
        
        out = self.dropout(out)
        out = self.fc1(out)
        out = self.relu(out)
        out = self.fc2(out)
        return self.sigmoid(out)

# --- 2. Real-Time Feature Extractor ---
def get_system_snapshot():
    """
    Collects a system-wide snapshot using psutil to approximate 
    the MalMem2022 features your model was trained on.
    """
    try:
        # Get all processes once to ensure consistency
        # On Windows, retrieving handles usually requires Admin privileges
        attrs = ['pid', 'ppid', 'num_threads']
        # Only fetch handles if we are admin, otherwise skip to avoid errors
        try:
            # Check if we can access handles (often restricted)
            p = psutil.Process()
            p.num_handles()
            attrs.append('num_handles')
            has_handles = True
        except:
            has_handles = False

        procs = [p.info for p in psutil.process_iter(attrs)]
        
        nproc = len(procs)
        if nproc == 0: return None

        # 1. pslist.nproc (Total processes)
        # 2. pslist.nppid (Total unique parent PIDs)
        ppids = set(p['ppid'] for p in procs if p['ppid'] is not None)
        nppid = len(ppids)

        # 3. pslist.avg_threads
        total_threads = sum(p['num_threads'] for p in procs if p['num_threads'])
        avg_threads = total_threads / nproc

        # 4. pslist.nprocs64bit (Approximate: assume most are 64bit on modern sys)
        nprocs64 = nproc  

        # 5. pslist.avg_handlers (Approximation)
        if has_handles:
            total_handles = sum(p.get('num_handles', 0) for p in procs)
            avg_handlers = total_handles / nproc
            nhandles = total_handles
        else:
            avg_handlers = 0
            nhandles = 0

        # --- DLLs & Services (Hard to get live without C++ drivers) ---
        # We fill these with mean values or zeros to satisfy the model input shape
        # In a real deployment, you would hook these or assume 0 for "normal"
        
        # Construct the 16-feature vector in the EXACT order of training:
        # ['pslist.nproc', 'pslist.nppid', 'pslist.avg_threads', 'pslist.nprocs64bit', 
        #  'pslist.avg_handlers', 'dlllist.ndlls', 'dlllist.avg_dlls_per_proc', 
        #  'handles.nhandles', 'handles.avg_handles_per_proc', 'svcscan.nservices', 
        #  'svcscan.kernel_drivers', 'svcscan.fs_drivers', 'svcscan.process_services', 
        #  'svcscan.shared_process_services', 'svcscan.interactive_process_services', 'svcscan.nactive']
        
        feature_vector = np.array([
            nproc,                  # pslist.nproc
            nppid,                  # pslist.nppid
            avg_threads,            # pslist.avg_threads
            nprocs64,               # pslist.nprocs64bit
            avg_handlers,           # pslist.avg_handlers
            1500,                   # dlllist.ndlls (Placeholder/Mean)
            40.0,                   # dlllist.avg_dlls_per_proc (Placeholder/Mean)
            nhandles,               # handles.nhandles
            avg_handlers,           # handles.avg_handles_per_proc
            300,                    # svcscan.nservices (Placeholder)
            200,                    # svcscan.kernel_drivers (Placeholder)
            26,                     # svcscan.fs_drivers (Placeholder)
            24,                     # svcscan.process_services (Placeholder)
            116,                    # svcscan.shared_process_services (Placeholder)
            0,                      # svcscan.interactive_process_services (Placeholder)
            120                     # svcscan.nactive (Placeholder)
        ]).reshape(1, -1)

        return feature_vector

    except Exception as e:
        print(f"Error collecting snapshot: {e}")
        return None