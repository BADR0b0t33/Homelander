import smtplib
from email.mime.text import MIMEText
from scapy.all import sniff, IP, TCP
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Define email configuration
EMAIL_FROM = 'your_email@example.com'
EMAIL_TO = 'recipient_email@example.com'
SMTP_SERVER = 'smtp.example.com'
SMTP_PORT = 587
SMTP_USERNAME = 'your_smtp_username'
SMTP_PASSWORD = 'your_smtp_password'

# Define a list of signatures/rules to detect suspicious behavior
signatures = [
    {"name": "SSH brute force", "src_port": None, "dst_port": 22, "threshold": 10},
    # Add more signatures/rules as needed
]

# Dictionary to store counters for each signature
signature_counters = {signature["name"]: 0 for signature in signatures}

# Feature extraction function
def extract_features(packet):
    features = []
    if IP in packet:
        features.append(packet[IP].src)
        features.append(packet[IP].dst)
        if TCP in packet:
            features.append(packet[TCP].sport)
            features.append(packet[TCP].dport)
            features.append(len(packet))
            # Add more features as needed
    return features

# Load dataset and train ML model
# Here, 'X' represents the feature matrix and 'y' represents the labels
# Replace this with your actual dataset
X = []
y = []

# Populate X and y with your dataset

# Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and train the ML model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Make predictions on the test set
y_pred = model.predict(X_test)

# Evaluate model performance
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy}")

# Function to predict if the packet is malicious
def predict_malicious(packet):
    features = [extract_features(packet)]
    prediction = model.predict(features)
    return prediction[0]

# Function to send email alerts
def send_email(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
    server.quit()

# Packet handling function
def packet_handler(packet):
    global signature_counters
    if IP in packet:  # Check if the packet is an IP packet
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address
        if TCP in packet:  # Check if the packet is a TCP packet
            tcp_sport = packet[TCP].sport  # Source port
            tcp_dport = packet[TCP].dport  # Destination port
            # Check if the packet is malicious
            if predict_malicious(packet):
                # Iterate through signatures to check for matches
                for signature in signatures:
                    if (signature["src_port"] is None or tcp_sport == signature["src_port"]) \
                            and tcp_dport == signature["dst_port"]:
                        # Increment the counter for this signature
                        signature_counters[signature["name"]] += 1
                        # Check if the threshold is exceeded
                        if signature_counters[signature["name"]] >= signature["threshold"]:
                            # Generate alert and send email
                            alert_message = f"Suspicious activity detected: {signature['name']} from {ip_src} to port {tcp_dport}"
                            send_email("Suspicious Activity Detected", alert_message)

# Sniff packets on the default network interface (change iface to specify a different interface)
sniff(prn=packet_handler, store=0)
