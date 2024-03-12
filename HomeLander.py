import smtplib
from email.mime.text import MIMEText 
from scapy.all import sniff, IP, TCP


# Define email configuration
EMAIL_FROM = 'ex: samse90@gmail.com'
EMAIL_TO = 'ex: bellaboy@gmail.com'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'Samse'
SMTP_PASSWORD = 'hototpic1234'


# Define a list of signatures/rules to detect suspicious behavior 
signatures = [
    {"name": "Network Reconnaissance", "src_port": None, "dst_port": [135, 139, 445], "threshold": 50},
    {"name": "Intrusion Attempt", "src_port": None, "dst_port": [22, 23, 3389], "threshold": 20},
    {"name": "Malware Infection", "src_port": None, "dst_port": None, "threshold": 30},
    {"name": "Data Exfiltration", "src_port": [80, 443], "dst_port": None, "threshold": 10},
    {"name": "Insider Threat", "src_port": None, "dst_port": None, "threshold": 5},
]
    # Add more signatures/rules as needed

# Dictionary to store counters for each signatures 
 Dictionary to store counters for each signature
signature_counters = {signature["name"]: 0 for signature in signatures}

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

# Function to handle captured packets
def packet_callback(packet):
    global signature_counters

    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Check if the packet matches any signature
        for signature in signatures:
            if (signature["src_port"] is None or src_port in signature["src_port"]) and \
               (signature["dst_port"] is None or dst_port in signature["dst_port"]):
                signature_counters[signature["name"]] += 1

                # If threshold is reached, send an alert email
                if signature_counters[signature["name"]] >= signature["threshold"]:
                    send_email(f'Security Alert: {signature["name"]}', f'Signature "{signature["name"]}" detected. Possible security threat!')

# Start packet sniffing
sniff(prn=packet_callback, store=0)


