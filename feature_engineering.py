import pandas as pd
import os

# ===============================
# 1. Load CSV file
# ===============================
input_file  = "stealth_detection_logs_cleaned.csv"
output_file = "CSV/ml_ready_dataset.csv"

# ── Large-file safety: read in chunks to avoid memory crash with 244MB+ CSVs ──
if os.path.exists(input_file) and os.path.getsize(input_file) > 50_000_000:  # >50 MB
    print(f"[FeatureEng] Large file detected ({os.path.getsize(input_file)//1_000_000} MB). Reading in chunks...")
    chunk_list = []
    for chunk in pd.read_csv(input_file, chunksize=50_000, low_memory=False):
        chunk_list.append(chunk)
    df = pd.concat(chunk_list, ignore_index=True)
    print(f"[FeatureEng] Loaded {len(df):,} rows.")
else:
    df = pd.read_csv(input_file, low_memory=False)

print("Original data loaded")
print(df.head())

# ===============================
# 2. Clean numeric columns
# ── Column-name compatibility: support both old schema (spaced) and new schema (underscored) ──
# ===============================

# AI Confidence column
if 'AI_Confidence' in df.columns:
    ai_conf_col = 'AI_Confidence'
elif 'AI Confidence' in df.columns:
    ai_conf_col = 'AI Confidence'
else:
    ai_conf_col = None

if ai_conf_col:
    df[ai_conf_col] = pd.to_numeric(
        df[ai_conf_col].astype(str).str.replace("%", "", regex=False),
        errors='coerce'
    ).fillna(0.0)

# Duration column
if 'Duration' in df.columns:
    df['Duration'] = pd.to_numeric(
        df['Duration'].astype(str).str.replace("s", "", regex=False),
        errors='coerce'
    ).fillna(0.0)

# Rate column
if 'Rate' in df.columns:
    df['Rate'] = pd.to_numeric(
        df['Rate'].astype(str).str.replace(" pps", "", regex=False),
        errors='coerce'
    ).fillna(0.0)

# ===============================
# 3. Create new attributes & Clean Advanced Features
# ===============================

# Advanced features to ensure numeric formatting
adv_features = ['Payload_Entropy', 'Packet_Size', 'Connection_Interval', 'SYN_Count', 'ACK_Count']
for feat in adv_features:
    if feat in df.columns:
        df[feat] = pd.to_numeric(df[feat], errors='coerce').fillna(0.0)

# Determine the packets column name (old: 'Packets', new: 'Packet_Count' or 'Connection_Count')
if 'Packet_Count' in df.columns:
    packets_col = 'Packet_Count'
elif 'Connection_Count' in df.columns:
    packets_col = 'Connection_Count'
elif 'Packets' in df.columns:
    packets_col = 'Packets'
else:
    packets_col = None

# Packets per second
if packets_col and 'Duration' in df.columns:
    df['Packets_Per_Second'] = df[packets_col] / df['Duration'].replace(0, 1)

# Simple port scan flag
if packets_col:
    df['Is_Port_Scan'] = df[packets_col].apply(lambda x: 1 if x > 15 else 0)

# Determine the detection method column
if 'Detection_Method' in df.columns:
    method_col = 'Detection_Method'
elif 'Method' in df.columns:
    method_col = 'Method'
else:
    method_col = None

# Convert Method text to numbers
if method_col:
    df['Method_Code'] = df[method_col].astype('category').cat.codes

# ===============================
# 4. Time-based attributes
# ===============================
if 'Timestamp' in df.columns:
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df['Hour']     = df['Timestamp'].dt.hour
    df['Is_Night'] = df['Hour'].apply(lambda x: 1 if (x >= 22 or x <= 5) else 0)

# ===============================
# 5. Create Label (Target column)
# ── Use 'Label' if already present, otherwise derive from method column ──
# ===============================
if 'Label' not in df.columns:
    if method_col:
        df['Label'] = df[method_col].apply(
            lambda x: 1 if ('GenAI' in str(x) or 'DPI' in str(x)) else 0
        )
    else:
        df['Label'] = 0  # default safe value
else:
    print("[FeatureEng] 'Label' column already present — keeping as-is.")

# ===============================
# 6. Drop columns not needed for ML
# ── Only drop columns that actually exist ──
# ===============================
cols_to_drop = []
for c in ['Timestamp', method_col, 'Source_IP', 'Source', 'Destination_IP', 'Destination',
          'Source_Port', 'Destination_Port', 'MAC_Address', 'Event_ID',
          'Flow_Start_Time', 'Last_Packet_Time', 'Detection_Time',
          'Malicious_Keyword', 'DPI_Result', 'Threat_Intelligence', 'Heuristic_Trigger',
          'GenAI_Result', 'Block_Rule_Name', 'Blocked_IP', 'Feature_Importance', 'System_Status',
          'Model_Training_Status', 'Log_Status', 'Security_Report_Status', 'Dataset_Source']:
    if c and c in df.columns:
        cols_to_drop.append(c)

df_ml = df.drop(columns=cols_to_drop)

# ===============================
# 7. Save ML-ready dataset
# ===============================
os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
df_ml.to_csv(output_file, index=False)

print("\nML-ready dataset created successfully!")
print("Saved as:", output_file)
print(df_ml.head())
print(f"Shape: {df_ml.shape}")
