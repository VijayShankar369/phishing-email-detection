-- Database schema for AI-Powered Phishing Email Detection System
-- MySQL Database Creation Script

-- Create the database
CREATE DATABASE IF NOT EXISTS phishing_detection 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE phishing_detection;

-- Table for storing email records
CREATE TABLE IF NOT EXISTS emails (
    id INT PRIMARY KEY AUTO_INCREMENT,
    sender_email VARCHAR(255),
    sender_name VARCHAR(255),
    receiver_email VARCHAR(255),
    subject TEXT,
    body TEXT,
    processed_text TEXT,
    urls TEXT,  -- JSON string of URLs
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_sender_email (sender_email),
    INDEX idx_timestamp (timestamp)
);

-- Table for storing prediction results
CREATE TABLE IF NOT EXISTS predictions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email_id INT,
    model_name VARCHAR(50) NOT NULL,
    prediction INT NOT NULL,  -- 0 = legitimate, 1 = phishing
    prediction_label VARCHAR(20) NOT NULL,
    confidence FLOAT DEFAULT 0.0,
    probability_legitimate FLOAT DEFAULT 0.0,
    probability_phishing FLOAT DEFAULT 0.0,
    risk_score FLOAT DEFAULT 0.0,
    suspicious_indicators TEXT,  -- JSON string
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
    INDEX idx_email_id (email_id),
    INDEX idx_model_name (model_name),
    INDEX idx_prediction (prediction),
    INDEX idx_timestamp (timestamp)
);

-- Table for user activity tracking
CREATE TABLE IF NOT EXISTS user_activity (
    id INT PRIMARY KEY AUTO_INCREMENT,
    session_id VARCHAR(100),
    action VARCHAR(50) NOT NULL,
    email_content_hash VARCHAR(64),
    prediction_result VARCHAR(20),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    
    INDEX idx_session_id (session_id),
    INDEX idx_action (action),
    INDEX idx_timestamp (timestamp)
);

-- Table for system configuration
CREATE TABLE IF NOT EXISTS system_config (
    id INT PRIMARY KEY AUTO_INCREMENT,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Table for model performance metrics
CREATE TABLE IF NOT EXISTS model_metrics (
    id INT PRIMARY KEY AUTO_INCREMENT,
    model_name VARCHAR(50) NOT NULL,
    metric_name VARCHAR(50) NOT NULL,
    metric_value FLOAT NOT NULL,
    evaluation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    dataset_size INT,
    notes TEXT,
    
    INDEX idx_model_name (model_name),
    INDEX idx_metric_name (metric_name),
    INDEX idx_evaluation_date (evaluation_date)
);

-- Table for suspicious keywords tracking
CREATE TABLE IF NOT EXISTS suspicious_keywords (
    id INT PRIMARY KEY AUTO_INCREMENT,
    keyword VARCHAR(100) NOT NULL,
    category VARCHAR(50),
    weight FLOAT DEFAULT 1.0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_keyword (keyword),
    INDEX idx_category (category),
    INDEX idx_is_active (is_active)
);

-- Table for URL patterns tracking
CREATE TABLE IF NOT EXISTS url_patterns (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pattern VARCHAR(255) NOT NULL,
    pattern_type ENUM('suspicious', 'legitimate', 'shortened') NOT NULL,
    weight FLOAT DEFAULT 1.0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_pattern_type (pattern_type),
    INDEX idx_is_active (is_active)
);

-- Create views for common queries
-- View for recent phishing detections
CREATE OR REPLACE VIEW recent_phishing_detections AS
SELECT 
    e.id,
    e.sender_email,
    e.subject,
    p.prediction_label,
    p.confidence,
    p.risk_score,
    p.timestamp
FROM emails e
JOIN predictions p ON e.id = p.email_id
WHERE p.model_name = 'ensemble' 
    AND p.prediction = 1
    AND p.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
ORDER BY p.timestamp DESC;

-- View for model performance summary
CREATE OR REPLACE VIEW model_performance_summary AS
SELECT 
    model_name,
    COUNT(*) as total_predictions,
    SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END) as phishing_detected,
    AVG(confidence) as avg_confidence,
    AVG(risk_score) as avg_risk_score,
    DATE(timestamp) as prediction_date
FROM predictions
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY model_name, DATE(timestamp)
ORDER BY prediction_date DESC, model_name;

-- View for daily statistics
CREATE OR REPLACE VIEW daily_statistics AS
SELECT 
    DATE(p.timestamp) as date,
    COUNT(*) as total_emails,
    SUM(CASE WHEN p.prediction = 1 THEN 1 ELSE 0 END) as phishing_count,
    SUM(CASE WHEN p.prediction = 0 THEN 1 ELSE 0 END) as legitimate_count,
    ROUND(AVG(p.confidence), 3) as avg_confidence,
    ROUND(AVG(p.risk_score), 2) as avg_risk_score
FROM predictions p
WHERE p.model_name = 'ensemble'
    AND p.timestamp >= DATE_SUB(NOW(), INTERVAL 90 DAY)
GROUP BY DATE(p.timestamp)
ORDER BY date DESC;

-- Create stored procedures for common operations
DELIMITER //

-- Procedure to clean old records
CREATE PROCEDURE CleanOldRecords(IN days_to_keep INT)
BEGIN
    DECLARE cutoff_date DATETIME;
    SET cutoff_date = DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    
    -- Start transaction
    START TRANSACTION;
    
    -- Delete old user activity records
    DELETE FROM user_activity WHERE timestamp < cutoff_date;
    
    -- Delete old prediction records (this will cascade to emails if no other references)
    DELETE FROM predictions WHERE timestamp < cutoff_date;
    
    -- Delete orphaned email records
    DELETE FROM emails 
    WHERE timestamp < cutoff_date 
    AND id NOT IN (SELECT DISTINCT email_id FROM predictions WHERE email_id IS NOT NULL);
    
    COMMIT;
    
    SELECT 'Cleanup completed successfully' as message;
END //

-- Procedure to get prediction statistics
CREATE PROCEDURE GetPredictionStats(IN days_back INT)
BEGIN
    DECLARE cutoff_date DATETIME;
    SET cutoff_date = DATE_SUB(NOW(), INTERVAL days_back DAY);
    
    SELECT 
        COUNT(*) as total_predictions,
        SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END) as phishing_detected,
        SUM(CASE WHEN prediction = 0 THEN 1 ELSE 0 END) as legitimate_emails,
        ROUND((SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END) / COUNT(*)) * 100, 2) as phishing_rate,
        ROUND(AVG(confidence), 3) as average_confidence,
        SUM(CASE WHEN risk_score > 70 THEN 1 ELSE 0 END) as high_risk_emails
    FROM predictions 
    WHERE model_name = 'ensemble' 
    AND timestamp >= cutoff_date;
END //

DELIMITER ;

-- Insert default configuration values
INSERT INTO system_config (config_key, config_value, description) VALUES
('model_version', '1.0.0', 'Current model version'),
('last_training_date', '2024-01-01', 'Last model training date'),
('prediction_threshold', '0.5', 'Threshold for phishing classification'),
('max_email_length', '10000', 'Maximum email length for processing'),
('cleanup_interval_days', '90', 'Days to keep old records')
ON DUPLICATE KEY UPDATE config_value = VALUES(config_value);

-- Insert default suspicious keywords
INSERT INTO suspicious_keywords (keyword, category, weight) VALUES
('urgent', 'urgency', 5.0),
('verify', 'verification', 4.0),
('suspended', 'threat', 6.0),
('click here', 'call_to_action', 4.5),
('limited time', 'urgency', 5.5),
('act now', 'urgency', 5.0),
('congratulations', 'prize', 4.0),
('winner', 'prize', 4.5),
('lottery', 'prize', 6.0),
('prize', 'prize', 4.0),
('free money', 'offer', 7.0),
('guaranteed', 'offer', 3.5),
('risk free', 'offer', 4.0),
('no obligation', 'offer', 3.0),
('confirm identity', 'verification', 5.5),
('account suspended', 'threat', 7.0),
('security alert', 'threat', 5.0),
('update payment', 'financial', 6.0),
('wire transfer', 'financial', 7.5),
('social security', 'personal_info', 8.0)
ON DUPLICATE KEY UPDATE weight = VALUES(weight);

-- Insert default URL patterns
INSERT INTO url_patterns (pattern, pattern_type, weight) VALUES
('bit\\.ly', 'shortened', 3.0),
('tinyurl\\.com', 'shortened', 3.0),
('goo\\.gl', 'shortened', 3.0),
('t\\.co', 'shortened', 2.5),
('ow\\.ly', 'shortened', 3.0),
('\\d+\\.\\d+\\.\\d+\\.\\d+', 'suspicious', 6.0),
('[a-z]+\\d+[a-z]+\\.com', 'suspicious', 4.0),
('secure.*bank.*\\.tk', 'suspicious', 8.0),
('paypal.*verify.*\\.tk', 'suspicious', 9.0)
ON DUPLICATE KEY UPDATE weight = VALUES(weight);

-- Create indexes for better performance
CREATE INDEX idx_emails_sender_timestamp ON emails(sender_email, timestamp);
CREATE INDEX idx_predictions_model_timestamp ON predictions(model_name, timestamp);
CREATE INDEX idx_user_activity_session_timestamp ON user_activity(session_id, timestamp);

-- Grant necessary permissions (adjust username as needed)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON phishing_detection.* TO 'phishing_user'@'localhost';
-- FLUSH PRIVILEGES;

-- Display table information
SHOW TABLES;

SELECT 'Database schema created successfully!' as status;