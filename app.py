import streamlit as st
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import os
import time
import random
from datetime import datetime
import pandas as pd

# Files
SMTP_FILE = "smtps.json"
LOGS_FILE = "logs.json"

# Simple storage
def save_data(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f)

def load_data(filename, default=[]):
    try:
        if os.path.exists(filename):
            with open(filename, "r") as f:
                return json.load(f)
        return default
    except:
        return default

# SMTP Class - SIMPLE & RELIABLE
class SMTPManager:
    def __init__(self):
        self.smtps = load_data(SMTP_FILE)
        self.logs = load_data(LOGS_FILE)

    def add_smtp(self, server, port, user, password, name="SMTP"):
        smtp = {
            "server": server,
            "port": port,
            "user": user,
            "password": password,
            "name": name
        }
        self.smtps.append(smtp)
        save_data(self.smtps, SMTP_FILE)
        return True

    def test_smtp(self, smtp):
        try:
            server = smtplib.SMTP(smtp["server"], smtp["port"], timeout=10)
            server.starttls()
            server.login(smtp["user"], smtp["password"])
            server.quit()
            return True
        except:
            return False

    def get_working(self):
        working = []
        for smtp in self.smtps:
            if self.test_smtp(smtp):
                working.append(smtp)
        return working

    def send_email(self, smtp, to_email, subject, body):
        try:
            msg = MIMEMultipart()
            msg['From'] = smtp["user"]
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))
            
            server = smtplib.SMTP(smtp["server"], smtp["port"], timeout=10)
            server.starttls()
            server.login(smtp["user"], smtp["password"])
            server.send_message(msg)
            server.quit()
            return True
        except:
            return False

    def run_campaign(self, targets, subject, body, delay=2):
        working_smtps = self.get_working()
        if not working_smtps:
            return "No working SMTPs"
        
        results = []
        smtp_idx = 0
        
        for i, email in enumerate(targets):
            smtp = working_smtps[smtp_idx % len(working_smtps)]
            success = self.send_email(smtp, email, subject, body)
            results.append({"email": email, "status": "✅" if success else "❌", "smtp": smtp["name"]})
            
            smtp_idx += 1
            time.sleep(delay)
            
            # Update progress
            progress = (i + 1) / len(targets) * 100
            st.session_state.progress = progress
            st.session_state.results = results[-10:]  # Last 10
            
            save_data(self.logs, LOGS_FILE)
        
        return results

# UI
st.set_page_config(page_title="🔥 PENTEST MAILER", layout="wide")
st.markdown("<h1 style='color: #00ff88; text-align: center;'>🔥 PEN TEST MAILER v5.0</h1>", unsafe_allow_html=True)

# Init
if 'manager' not in st.session_state:
    st.session_state.manager = SMTPManager()
    st.session_state.progress = 0
    st.session_state.results = []

manager = st.session_state.manager

# TABS
tab1, tab2, tab3 = st.tabs(["1️⃣ SMTP Manager", "2️⃣ Targets", "3️⃣ LAUNCH"])

with tab1:
    st.header("⚙️ SMTP MANAGER")
    
    # Add SMTP
    col1, col2 = st.columns(2)
    with col1:
        server = st.text_input("Server", "smtp-mail.outlook.com")
        port = st.number_input("Port", 587)
    with col2:
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
    
    if st.button("➕ ADD SMTP", type="primary"):
        if email:
            manager.add_smtp(server, port, email, password, email.split("@")[0])
            st.success("✅ SMTP Added!")
            st.rerun()
    
    # Status
    st.subheader("📊 STATUS")
    working = manager.get_working()
    col1, col2 = st.columns(2)
    col1.metric("Total", len(manager.smtps))
    col2.metric("🟢 Working", len(working))
    
    # List
    if manager.smtps:
        for i, smtp in enumerate(manager.smtps):
            status = "🟢" if manager.test_smtp(smtp) else "🔴"
            col1, col2 = st.columns([3, 1])
            col1.caption(f"{status} {smtp['name']} - {smtp['user']}")
            if col2.button("🗑️", key=f"del_{i}"):
                manager.smtps.pop(i)
                save_data(manager.smtps, SMTP_FILE)
                st.rerun()

with tab2:
    st.header("🎯 TARGETS")
    targets_input = st.text_area("Paste emails (1 per line)", height=200)
    if targets_input.strip():
        targets = [line.strip() for line in targets_input.split("\n") if "@" in line.strip()]
        st.success(f"✅ {len(targets)} targets ready")
        st.session_state.targets = targets
        st.caption(f"Preview: {targets[:5]}...")

with tab3:
    st.header("🚀 LAUNCH CAMPAIGN")
    
    targets = st.session_state.get('targets', [])
    working = manager.get_working()
    
    if not targets:
        st.error("❌ Load targets first")
    elif not working:
        st.error("❌ Add working SMTPs first")
    else:
        st.success(f"✅ READY: {len(targets)} targets × {len(working)} SMTPs")
        
        subject = st.text_input("Subject", "🚨 URGENT Security Alert")
        
        body = st.text_area("Email Body", height=150, value="""
        <h2>🚨 ACTION REQUIRED</h2>
        <p>Click <a href="{link}">here</a> to verify your account</p>
        <p>ID: {id}</p>
        """)
        
        delay = st.slider("Delay (seconds)", 1, 10, 2)
        
        if st.button(f"🔥 LAUNCH ({len(targets)} emails)", type="primary"):
            # Replace placeholders
            link = "https://your-phish.com/track"
            final_body = body.format(link=link, id=f"PT{random.randint(10000,99999)}")
            
            with st.spinner("🚀 Sending..."):
                results = manager.run_campaign(targets, subject, final_body, delay)
            
            st.balloons()
            st.success("🎉 CAMPAIGN COMPLETE!")

# Progress & Results
col1, col2, col3 = st.columns(3)
col1.metric("Progress", f"{st.session_state.progress:.1f}%")
col2.metric("Targets", len(st.session_state.get('targets', [])))
col3.metric("Working SMTPs", len(manager.get_working()))

# Live Results
if st.session_state.results:
    st.subheader("📊 LIVE RESULTS")
    df = pd.DataFrame(st.session_state.results)
    st.dataframe(df, use_container_width=True)

# Logs
if os.path.exists(LOGS_FILE):
    logs = pd.DataFrame(manager.logs)
    if not logs.empty:
        st.subheader("📈 HISTORY")
        st.dataframe(logs.tail(20))
