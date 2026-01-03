import streamlit as st
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time
import threading
import random
import json
import os
from datetime import datetime
import plotly.express as px

# Config
SMTP_FILE = "smtps.json"
STATS_FILE = "stats.json"
st.set_page_config(page_title="🔥 PenTest Mailer Pro", layout="wide", initial_sidebar_state="expanded")

@st.cache_data
def load_json(file):
    try:
        return json.load(open(file))
    except:
        return []

def save_json(data, file):
    with open(file, 'w') as f:
        json.dump(data, f, indent=2)

# Cyberpunk CSS
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
    
html, body, [class*="css"]  {
    font-family: 'Orbitron', monospace !important;
    background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
}
.stApp {
    background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
}
h1 {color: #00ff88 !important; font-weight: 900; text-shadow: 0 0 20px #00ff88;}
.metric {background: rgba(0,255,136,0.1); border: 1px solid #00ff88;}
.stButton > button {
    background: linear-gradient(45deg, #ff0080, #00ff88, #0080ff);
    color: white !important;
    border: none;
    border-radius: 15px;
    font-weight: bold;
    box-shadow: 0 4px 15px rgba(0,255,136,0.3);
    transition: all 0.3s;
}
.stButton > button:hover {
    transform: scale(1.05);
    box-shadow: 0 6px 25px rgba(0,255,136,0.5);
}
.textbox {border-radius: 10px; border: 2px solid #00ff88;}
.progress {background-color: #16213e;}
</style>
""", unsafe_allow_html=True)

class Mailer:
    def __init__(self):
        self.smtps = load_json(SMTP_FILE)
        self.stats = load_json(STATS_FILE)

    def add_smtp(self, config):
        self.smtps.append(config)
        save_json(self.smtps, SMTP_FILE)

    def test_smtp(self, idx):
        if 0 <= idx < len(self.smtps):
            config = self.smtps[idx]
            try:
                server = smtplib.SMTP(config['server'], config['port'], timeout=10)
                server.starttls()
                server.login(config['user'], config['pass'])
                server.quit()
                return True, "🟢 SMTP OK"
            except Exception as e:
                return False, f"🔴 {str(e)[:100]}"
        return False, "Invalid SMTP index"

    def send_campaign(self, targets, subject, template, phishing_url, delay=30):
        results = []
        total = len(targets)
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def worker():
            for i, email in enumerate(targets):
                sent = False
                for smtp_idx, smtp in enumerate(self.smtps):
                    success, msg = self._send_single(smtp, email, subject, template, phishing_url)
                    if success:
                        results.append({"email": email, "status": "✅ SENT", "smtp": smtp_idx+1})
                        sent = True
                        break
                    time.sleep(1)
                
                if not sent:
                    results.append({"email": email, "status": "❌ FAILED", "smtp": 0})
                
                progress = (i+1)/total
                progress_bar.progress(progress)
                status_text.text(f"📤 {sum(1 for r in results if r['status']=='✅ SENT')} / {i+1}/{total}")
                time.sleep(delay)
        
        threading.Thread(target=worker, daemon=True).start()
        save_json(results, STATS_FILE)
        return results
    
    def _send_single(self, config, to_email, subject, template, phishing_url):
        try:
            uid = f"pt_{random.randint(100000,999999)}_{int(time.time())}"
            body = template.format(phishing_link=phishing_url, uid=uid, email=to_email)
            
            server = smtplib.SMTP(config['server'], config['port'], timeout=10)
            server.starttls()
            server.login(config['user'], config['pass'])
            
            msg = MIMEMultipart()
            msg['From'] = config['user']
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))
            
            server.send_message(msg)
            server.quit()
            return True, "Sent"
        except Exception as e:
            return False, str(e)

# Initialize session state
if 'mailer' not in st.session_state:
    st.session_state.mailer = Mailer()

mailer = st.session_state.mailer

# Header
st.title("🔥 **PEN TEST MAILER PRO v3.0**")
st.markdown("**5x SMTP Rotation • Unlimited Targets • Custom Templates • Pixel Tracking**")

# Sidebar: SMTP Manager (5 Accounts Max)
with st.sidebar:
    st.header("⚙️ **SMTP MANAGER** (Max 5)")
    
    # Add SMTP Form
    with st.expander("➕ **ADD SMTP ACCOUNT**", expanded=False):
        st.markdown("**Free accounts work best:**")
        st.markdown("• `smtp-mail.outlook.com:587` (300/day)")
        st.markdown("• `smtp.gmail.com:587` (App Password)")
        st.markdown("• `smtp.elasticemail.com:2525` (1000/day)")
        
        # Use session state for input persistence
        if 'smtp_inputs' not in st.session_state:
            st.session_state.smtp_inputs = {
                'server': 'smtp-mail.outlook.com',
                'port': 587,
                'username': '',
                'password': ''
            }
        
        col1, col2 = st.columns(2)
        with col1:
            st.session_state.smtp_inputs['server'] = st.text_input("Server", 
                value=st.session_state.smtp_inputs['server'], key="smtp_server")
            st.session_state.smtp_inputs['port'] = st.number_input("Port", 
                value=st.session_state.smtp_inputs['port'], key="smtp_port")
        with col2:
            st.session_state.smtp_inputs['username'] = st.text_input("Email/Username", key="smtp_username")
            st.session_state.smtp_inputs['password'] = st.text_input("Password", type="password", key="smtp_password")
        
        if st.button("**🚀 ADD & TEST**", use_container_width=True, type="primary"):
            config = {
                "server": st.session_state.smtp_inputs['server'],
                "port": int(st.session_state.smtp_inputs['port']),
                "user": st.session_state.smtp_inputs['username'],
                "pass": st.session_state.smtp_inputs['password'],
                "name": st.session_state.smtp_inputs['username'].split('@')[0][:10] if '@' in st.session_state.smtp_inputs['username'] else "SMTP"
            }

            if len(mailer.smtps) < 5:
                with st.spinner("🧪 Testing SMTP connection..."):
                    # Test before adding
                    test_server = smtplib.SMTP(config['server'], config['port'], timeout=10)
                    test_server.starttls()
                    test_server.login(config['user'], config['pass'])
                    test_server.quit()
                
                mailer.add_smtp(config)
                st.session_state.mailer.smtps = mailer.smtps  # Update session state
                st.success(f"✅ **{config['name']}** added & tested successfully!")
                st.rerun()
            else:
                st.error("❌ **Max 5 accounts** - delete one first")

    # SMTP Status Grid
    st.header("📊 **SMTP STATUS**")
    if mailer.smtps:
        for i, smtp in enumerate(mailer.smtps):
            col1, col2, col3 = st.columns([2,1,1])
            col1.metric(smtp.get('name', 'SMTP'), smtp['user'])

            if col2.button("🧪 **TEST**", key=f"test_{i}"):
                with st.spinner(f"Testing {smtp['user']}..."):
                    success, msg = mailer.test_smtp(i)
                    if success:
                        st.success(msg)
                    else:
                        st.error(msg)

            if col3.button("🗑️", key=f"d{i}"):
                mailer.smtps.pop(i)
                save_json(mailer.smtps, SMTP_FILE)
                st.session_state.mailer.smtps = mailer.smtps
                st.rerun()
    else:
        st.warning("👆 **Add your first SMTP account**")

# Rest of the code remains the same...
# Main Campaign Tab
st.header("📨 **LAUNCH CAMPAIGN**")
tab1, tab2, tab3 = st.tabs(["🎯 Targets", "✉️ Message", "🚀 Send"])

with tab1:
    st.subheader("📧 **Target Emails** (Unlimited - 2000+ OK)")
    email_input = st.text_area("**Paste emails (1 per line)**", 
        placeholder="ceo@target.com\nhr@target.com\nadmin@target.com\n...", 
        height=300, help="Unlimited emails supported")
    
    if email_input.strip():
        targets = [line.strip() for line in email_input.strip().split('\n') 
                  if '@' in line and line.strip()]
        st.success(f"✅ **{len(targets)} targets loaded**")
        st.session_state.targets = targets  # Store in session state
        st.dataframe(pd.DataFrame({"Email": targets}), use_container_width=True)
    else:
        st.warning("👆 **Paste your target emails**")

with tab2:
    st.subheader("✉️ **Message Settings**")
    
    col1, col2 = st.columns(2)
    with col1:
        subject = st.text_input("📋 Subject", "🚨 URGENT: Account Security Alert")
        st.subheader("🔗 **Phishing Link**")
        phishing_url = st.text_input("Your tracking/phishing URL", 
            placeholder="https://your-phish.com/track?id={uid}")
    
    with col2:
        st.subheader("📄 **HTML Template Editor**")
        template = st.text_area("Edit template", height=250, 
        value="""<div style="max-width: 600px; margin: 0 auto; padding: 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.3);">
<h1 style="text-align: center; margin: 0 0 20px;">🚨 SECURITY ALERT</h1>
<p style="font-size: 18px; line-height: 1.6;">Your account <strong>{email}</strong> requires immediate verification.</p>
<div style="text-align: center; margin: 30px 0;">
    <a href="{phishing_link}" style="background: #ff4757; color: white; padding: 15px 40px; text-decoration: none; border-radius: 50px; font-size: 18px; font-weight: bold; display: inline-block; box-shadow: 0 10px 30px rgba(255,71,87,0.4); transition: all 0.3s;">
        🔒 VERIFY ACCOUNT NOW
    </a>
</div>
<p style="font-size: 14px; opacity: 0.9;">Ref: {uid} | This is an automated security notification</p>
<!-- Pixel tracker -->
<img src="{phishing_link.replace('phish','track')}&pixel=1" width="1" height="1" style="display:none;">
</div>""")

with tab3:
    targets = st.session_state.get('targets', [])
    if not targets or not mailer.smtps:
        st.error("❌ **Setup required:** Add SMTP accounts + paste targets")
    else:
        col1, col2 = st.columns(2)
        with col1:
            delay = st.slider("⏱️ Delay between emails", 10, 120, 30)
        with col2:
            threads = st.slider("⚡ Parallel threads", 1, 3, 1)
        
        if st.button("🚀 **LAUNCH FULL CAMPAIGN**", type="primary", use_container_width=True):
            with st.spinner("🔥 Launching campaign..."):
                results = mailer.send_campaign(targets, subject, template, phishing_url, delay)
            st.balloons()
            st.success("🎉 **CAMPAIGN LAUNCHED!** Check stats below.")

# Stats Dashboard
st.header("📊 **CAMPAIGN STATS**")
if os.path.exists(STATS_FILE):
    stats = pd.DataFrame(load_json(STATS_FILE))
    if not stats.empty:
        col1, col2, col3, col4 = st.columns(4)
        sent_count = len(stats[stats['status']=='✅ SENT'])
        total_count = len(stats)
        col1.metric("✅ Sent", sent_count)
        col2.metric("❌ Failed", len(stats[stats['status']=='❌ FAILED']))
        col3.metric("📧 Total", total_count)
        col4.metric("🎯 Success %", f"{sent_count/total_count*100:.1f}%" if total_count > 0 else "0%")
        
        fig = px.bar(stats['status'].value_counts().reset_index(), 
                    x='status', y='count', title="📈 Send Results",
                    color='count', color_continuous_scale='viridis')
        st.plotly_chart(fig, use_container_width=True)
        
        st.dataframe(stats.tail(50))
    else:
        st.info("👆 **Run your first campaign**")
else:
    st.info("👆 **Run campaign to see stats**")

# Footer
st.markdown("---")
st.markdown("*🔒 Authorized Penetration Testing Tool • Deployed on Railway*")
