import os
import time
import json
import logging
import schedule
import psycopg2
from psycopg2.extras import RealDictCursor
import pandas as pd
from sklearn.ensemble import IsolationForest

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ai-engine')

DB_URL = os.getenv('DATABASE_URL', 'postgres://waf_user:waf_password@postgres:5432/waf_db?sslmode=disable')

def get_db_connection():
    return psycopg2.connect(DB_URL)

def extract_features(event):
    raw_log_str = event.get('raw_log', '{}')
    try:
        log_json = json.loads(raw_log_str)
    except json.JSONDecodeError:
        log_json = {}

    req_uri = log_json.get('transaction', {}).get('request', {}).get('uri', event.get('path', ''))
    req_headers = log_json.get('transaction', {}).get('request', {}).get('headers', {})
    
    # Feature 1: Path length
    path_len = len(req_uri) if req_uri else 0
    
    # Feature 2: Number of headers
    header_count = len(req_headers)
    
    # Feature 3: Special characters ratio in URI
    special_chars = sum(1 for c in req_uri if not c.isalnum() and c not in ['/', '-', '_', '.']) if req_uri else 0
    special_ratio = special_chars / max(path_len, 1)

    return {
        'id': event['id'],
        'client_ip': event['client_ip'],
        'path_len': path_len,
        'header_count': header_count,
        'special_ratio': special_ratio
    }

def run_anomaly_detection():
    logger.info("Starting anomaly detection cycle...")
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Fetch last 1000 events
        cursor.execute("SELECT id, client_ip, path, raw_log FROM security_events ORDER BY id DESC LIMIT 1000")
        events = cursor.fetchall()
        
        if len(events) < 50:
            logger.info("Not enough data to train model (need at least 50 events).")
            cursor.close()
            conn.close()
            return

        # Extract features
        features = [extract_features(e) for e in events if e.get('client_ip')]
        df = pd.DataFrame(features)
        
        if df.empty:
            return

        X = df[['path_len', 'header_count', 'special_ratio']].fillna(0)
        
        # Train Isolation Forest
        model = IsolationForest(contamination=0.02, random_state=42)
        model.fit(X)
        
        # Predict (-1 is anomaly, 1 is normal)
        predictions = model.predict(X)
        df['anomaly'] = predictions
        
        # Filter anomalies
        anomalies = df[df['anomaly'] == -1]
        anomalous_ips = anomalies['client_ip'].unique()
        
        if len(anomalous_ips) > 0:
            logger.info(f"Detected {len(anomalous_ips)} anomalous IPs: {anomalous_ips}")
            for ip in anomalous_ips:
                # Extract representative feature vector for the IP
                ip_rows = anomalies[anomalies['client_ip'] == ip]
                feat_sample = ip_rows[['path_len', 'header_count', 'special_ratio']].iloc[0].to_dict()
                
                # 1. Insert into ai_anomaly_signals (Policy Engine 2.0 Signal Provider)
                cursor.execute("""
                    INSERT INTO ai_anomaly_signals (client_ip, anomaly_score, observed_features, recommended_action, status)
                    VALUES (%s, 0.875, %s, 'CHALLENGE', 'SIGNAL_ACTIVE')
                """, (ip, json.dumps(feat_sample)))

                # 2. Update threat_indicators with CHALLENGE action instead of hard BLOCK
                cursor.execute("""
                    INSERT INTO threat_indicators (indicator, indicator_type, threat_category, confidence_score, severity, action, source_feed, is_active)
                    VALUES (%s, 'IP', 'AI_ANOMALY', 85, 'HIGH', 'CHALLENGE', 'AI_ANOMALY', TRUE)
                    ON CONFLICT (indicator) DO UPDATE SET 
                        confidence_score = 85, 
                        action = 'CHALLENGE',
                        updated_at = CURRENT_TIMESTAMP
                """, (ip,))
            conn.commit()
        else:
            logger.info("No new anomalies detected.")
            
        cursor.close()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error during anomaly detection: {e}")

def main():
    logger.info("AI Engine initialized. Waiting for DB connection...")
    time.sleep(5) # Wait for Postgres to be ready
    
    # Run once at startup
    run_anomaly_detection()
    
    # Schedule every 5 minutes
    schedule.every(5).minutes.do(run_anomaly_detection)
    
    while True:
        schedule.run_pending()
        time.sleep(10)

if __name__ == "__main__":
    main()
