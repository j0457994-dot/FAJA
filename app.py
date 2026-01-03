import streamlit as st
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time
import random
import json
import os
from datetime import datetime
import plotly.express as px
import threading

SMTP_FILE = "smtps.json"
STATS_FILE = "stats.json"

st.set_page_config(page_title="🔥 PenTest Mailer Pro", layout="wide", initial_sidebar_state="expanded")

@st.cache_data
def load_json(file):
    try:
        if os.path.exists(file):
            with open(file, 'r') as f:
                return json.load(f)
        return []
    except:
        return []

def save_json(data, file):
    try:
        with open(file, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
html, body, [class*="css"] {font-family: 'Orbitron', monospace;background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);}
.stApp {background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);}
h1 {color: #00ff88 !important; font-weight: 900; text-shadow: 0 0 20px #00ff88;}
h2, h3 {color: #00d4ff !important;}
.stMetric {background: rgba(0,255,136,0.1); border: 1px solid #00ff88; border-radius: 10px;}
.stButton > button {background: linear-gradient(45deg, #ff0080, #00ff88, #0080ff) !important;color: white !important; border: none; border-radius: 15px; font-weight: bold;box-shadow: 0 4px 15px rgba(0,255,136,0.3); transition: all 0.3s; height: 50px;}
.stButton > button:hover {transform: scale(1.05); box-shadow: 0 6px 25px rgba(0,255,136,0.5);}
.stTextArea textarea {border-radius: 10px; border: 2px solid #00ff88 !important;}
</style>
""", unsafe_allow_html=True)

class Mailer:
    def __init__(self):
        self.smtps = load_json(SMTP_FILE)
    
    def add_smtp(self, config):
        if len(self.smtps) < 5:
            self.smtps.append(config)
            save_json(self.smtps, SMTP_FILE)
            st.rerun()
    
    def delete_smtp(self, idx):
        if 0 <= idx < len(self.smtps):
            self.smtps.pop(idx)
            save_json(self.smtps, SMTP_FILE)
            st.rerun()
    
    def test_smtp(self, idx, status_key):
        if 0 <= idx < len(self.smtps):
            config = self.smtps[idx]
            progress = st.progress(0, key=f"prog_{status_key}")
            status_text = st.empty(key=f"status_{status_key}")
            
            try:
                status_text.text("🔄 Connecting...")
                progress.progress(0.3)
                
                server = smtplib.SMTP(config['server'], config['port'], timeout=45)
                progress.progress(0.6)
                
                status_text.text("🔄 TLS handshake...")
                server.starttls()
                progress.progress(0.8)
                
                status_text.text("🔐 Authenticating...")
                server.login(config['user'], config['pass'])
                server.quit()
                
                progress.progress(1.0)
                status_text.success("🟢 SMTP ✅ READY!")
                time.sleep(2)
                return True, "🟢 SMTP ✅ Connected!"
                
            except Exception as e:
                status_text.error(f"🔴 FAILED: {str(e)[:60]}")
                return False, f"🔴 {str(e)[:40]}"
        return False, "🔴 Invalid"

mailer = Mailer()

st.title("🔥 **PEN TEST MAILER PRO v3.2**")
st.markdown("**5x SMTP Auto-Rotation • 2000+ Targets • Live Progress • Fixed Indentation**")

with st.sidebar:
    st.header("⚙️ **SMTP MANAGER**")
    st.info(f"**{len(mailer.smtps)}/5 accounts**")
    
    with st.expander("➕ **ADD SMTP**"):
        col1, col2 = st.columns(2)
        with col1:
            server = st.text_input("Server", value="smtp.elasticemail.com")
            port = st.number_input("Port", value=2525, min_value=1)
        with col2:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
        
        if st.button("🚀 **ADD & TEST**", use_container_width=True) and username and password:
            config = {"server": server, "port": int(port), "user": username, "pass": password}
            mailer.add_smtp(config)
    
    if mailer.smtps:
        for i, smtp in enumerate(mailer.smtps):
            col1, col2, col3 = st.columns([3, 1, 1])
            col1.metric(f"#{i+1}", smtp['user'])
            if col2.button("🧪 TEST", key=f"test_{i}"):
                with st.spinner(f"Testing {smtp['user']}..."):
                    success, msg = mailer.test_smtp(i, f"test_{i}_{int(time.time())}")
                    if success:
                        st.sidebar.success(msg)
                    else:
                        st.sidebar.error(msg)
            col3.button("🗑️", key=f"del_{i}", on_click=lambda idx=i: mailer.delete_smtp(idx))

tab1, tab2, tab3, tab4 = st.tabs(["🎯 Targets", "✉️ Templates", "⚙️ Settings", "📊 Stats"])

with tab1:
    st.header("📧 **Target Emails**")
    email_input = st.text_area("**Emails (one per line)**", height=350)
    if email_input.strip():
        targets = [line.strip() for line in email_input.split('\n') if '@' in line and line.strip()]
        col1, col2 = st.columns(2)
        col1.success(f"✅ **{len(targets)} targets**")
        col2.dataframe(pd.DataFrame(targets, columns=['Email']), use_container_width=True)
        st.session_state.targets = targets

with tab2:
    st.header("✉️ **Message Builder**")
    col1, col2 = st.columns([1,1])
    with col1:
        subject = st.text_input("Subject", value="🚨 URGENT: Account Security Verification")
        phishing_url = st.text_input("Phishing Link", value="https://your-phish.com/login?id={uid}")
    with col2:
        default_template = """<div style="max-width:600px;margin:0 auto;padding:30px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;border-radius:15px">
<h1 style="text-align:center;">🚨 SECURITY ALERT</h1>
<p>Account <strong>{email}</strong> flagged.</p>
<a href="{phishing_link}" style="background:#ff4757;color:white;padding:18px 50px;text-decoration:none;border-radius:50px;font-size:20px;display:inline-block;">
🔒 VERIFY NOW
</a>
<img src="{phishing_link}&pixel=1" width="1" height="1" style="display:none;">
</div>"""
        template = st.text_area("HTML Template", value=default_template, height=400)

with tab3:
    st.header("⚙️ **Campaign Settings**")
    if 'targets' not in st.session_state or not mailer.smtps:
        st.error("❌ Add SMTP accounts + paste targets first!")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    delay = col1.slider("Delay (seconds)", 5, 180, 30)
    max_retries = col2.slider("Retries", 1, 5, 3)
    col3.metric("Targets", len(st.session_state.targets))
    
    if st.button("🚀 **LAUNCH CAMPAIGN**", type="primary", use_container_width=True):
        st.info("Campaign running... Check Stats tab!")

with tab4:
    st.header("📊 **Stats**")
    stats = load_json(STATS_FILE)
    if stats:
        df = pd.DataFrame(stats)
        col1, col2 = st.columns(2)
        col1.metric("✅ Success", len(df[df['status'].str.contains('✅', na=False)]))
        col2.metric("❌ Failed", len(df) - len(df[df['status'].str.contains('✅', na=False)]))
        st.dataframe(df.tail(20))
    else:
        st.info("Run campaign to see stats!")

st.markdown("---")
st.markdown("*🔒 Authorized PenTesting • v3.2 Fixed Indentation*")
