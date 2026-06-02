import os
import sqlite3
import logging
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "honeypot.db")
MODEL_PATH = os.path.join(BASE_DIR, "ml_model.joblib")

def extract_features():
    logging.info(f"Connecting to database at {DB_PATH}...")
    if not os.path.exists(DB_PATH):
        logging.error("Database not found! Start the honeypot and generate some traffic first.")
        return None

    conn = sqlite3.connect(DB_PATH)
    
    query = """
    SELECT 
        ip,
        timestamp,
        LENGTH(path) as path_len,
        LENGTH(query_string) as query_len,
        LENGTH(body_preview) as body_len,
        LENGTH(user_agent) as ua_len
    FROM honeypot_events
    """
    
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    if df.empty:
        logging.error("No data found in the database. Please generate some traffic first.")
        return None
        
    logging.info(f"Loaded {len(df)} historical events.")
    
    # Calculate velocity: requests per minute per IP
    # UTC strings can be parsed to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='ISO8601', errors='coerce')
    df['time_bin'] = df['timestamp'].dt.floor('min')
    
    velocity_counts = df.groupby(['ip', 'time_bin']).size().reset_index(name='velocity')
    df = pd.merge(df, velocity_counts, on=['ip', 'time_bin'], how='left')
    
    # Final feature set (drop non-numeric columns like ip, timestamp)
    features = df[['path_len', 'query_len', 'body_len', 'ua_len', 'velocity']]
    
    # Fill any NaNs with 0
    features = features.fillna(0)
    
    return features

def main():
    features = extract_features()
    if features is None:
        return
        
    if len(features) < 10:
        logging.warning("Warning: Very little data to train on. The model might not be robust.")

    logging.info("Training Isolation Forest anomaly detection model...")
    # contamination=0.05 implies we expect ~5% of traffic to be highly anomalous
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    
    model.fit(features)
    
    logging.info(f"Exporting trained model to {MODEL_PATH}...")
    joblib.dump(model, MODEL_PATH)
    
    logging.info("Done! The ML model is ready for live ASGI inference.")

if __name__ == "__main__":
    main()
