import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder

scaler = joblib.load(r"P:\SSM project\Models\Models_PKL\Scalers\intrusion_scaler.pkl")
scaler_1 = joblib.load(r"P:\SSM project\Models\Models_PKL\Scalers\server_scaler.pkl")
scaler_2 = joblib.load(r"P:\SSM project\Models\Models_PKL\Scalers\phishing_detection_scaler.pkl")

def preprocess_intrusion(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = df.columns.str.strip()
    if 'Label' in df.columns:
        df = df.drop(columns=['Label'])
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df = df.select_dtypes(include='number')
    df_clean = df.dropna().copy()  
    df_scaled = scaler.transform(df_clean)
    return df_scaled, df_clean.index 

def preprocess_incident_logs(df: pd.DataFrame) -> pd.DataFrame:
    df['sys_created_at'] = df['sys_created_at'].fillna(df['opened_at'])
    df['closed_at'] = df['closed_at'].fillna(df['opened_at'])
    date_cols = ['opened_at', 'sys_created_at', 'sys_updated_at', 'resolved_at', 'closed_at']
    for col in date_cols:
        df[col] = pd.to_datetime(df[col], errors='coerce')
    df['resolution_time_minutes'] = (df['resolved_at'] - df['opened_at']).dt.total_seconds() / 60
    df = df.dropna(subset=['resolution_time_minutes'])
    df['u_symptom'] = (
        "Category: " + df['category'].astype(str) +
        " | Subcategory: " + df['subcategory'].astype(str) +
        " | Closed Code: " + df['closed_code'].astype(str)
    )
    df = df.drop(columns=['resolved_at', 'opened_at'])
    return df

def preprocess_server_logs(df: pd.DataFrame) -> pd.DataFrame:
    def convert_bytes(x):
        x = str(x).strip()
        if 'M' in x:
            return float(x.replace('M', '').strip()) * 1_000_000
        elif 'K' in x:
            return float(x.replace('K', '').strip()) * 1_000
        else:
            try:
                return float(x)
            except:
                return 0.0

    df['Bytes'] = df['Bytes'].apply(convert_bytes)

    # Handle bad date formats gracefully
    df['Date first seen'] = pd.to_datetime(df['Date first seen'], errors='coerce')
    df = df.dropna(subset=['Date first seen']) # Drop rows with invalid dates

    df['year'] = df['Date first seen'].dt.year
    df['month'] = df['Date first seen'].dt.month
    df['day'] = df['Date first seen'].dt.day
    df['hour'] = df['Date first seen'].dt.hour
    df['minute'] = df['Date first seen'].dt.minute
    df['second'] = df['Date first seen'].dt.second
    df = df.drop(columns=['Date first seen'])

    cols_to_encode = ['Proto', 'Flags', 'Src IP Addr', 'Dst IP Addr']
    le = LabelEncoder()
    for col in cols_to_encode:
        df[col] = df[col].astype(str)
        df[col] = le.fit_transform(df[col])

    columns_to_scale = ['Duration', 'Src Pt', 'Dst Pt', 'Packets', 'Bytes', 'Flows']
    df[columns_to_scale] = scaler_1.fit_transform(df[columns_to_scale])

    return df


def preprocess_phishing(df: pd.DataFrame) -> pd.DataFrame:
    df.drop(columns=['url'], inplace=True)
    if 'status' in df.columns:
        df = df.drop(columns=['status'])
    df = scaler_2.transform(df)
    return df

def preprocess_ssh(df: pd.DataFrame) -> pd.DataFrame:
    df['Username'] = df['Username'].fillna('missing')
    df['Password'] = df['Password'].fillna('missing')
    df['datetime'] = pd.to_datetime(df['Date'] + ' ' + df['Time'], errors='coerce')
    df['hour'] = df['datetime'].dt.hour
    df['day'] = df['datetime'].dt.day
    df['weekday'] = df['datetime'].dt.weekday
    df['is_weekend'] = df['weekday'].apply(lambda x: 1 if x >= 5 else 0)

    df.drop(['Date', 'Time', 'datetime'], axis=1, inplace=True)
    categorical_cols = ['Username', 'Password', 'Country', 'City', 'IP']
    for col in categorical_cols:
        df[col] = df[col].astype(str)  
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])

    return df

