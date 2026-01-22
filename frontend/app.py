"""
CyberShield AI - Advanced Malware Detection
Frontend application connected to backend API
"""

import hashlib
import tempfile
import time
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

warnings.filterwarnings("ignore")

# API Configuration
API_BASE_URL = "http://localhost:8000"


# ==================== API CLIENT ====================
class APIClient:
    """Client for interacting with the backend API"""

    @staticmethod
    def get(endpoint: str) -> Dict[str, Any]:
        """GET request to API"""
        try:
            response = requests.get(f"{API_BASE_URL}{endpoint}", timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": str(e)}

    @staticmethod
    def post(endpoint: str, data: Dict = None, files: Dict = None, json: Dict = None) -> Dict[str, Any]:
        """POST request to API"""
        try:
            if files:
                response = requests.post(
                    f"{API_BASE_URL}{endpoint}", data=data, files=files, timeout=300
                )
            elif json:
                response = requests.post(
                    f"{API_BASE_URL}{endpoint}", json=json, timeout=30
                )
            else:
                response = requests.post(
                    f"{API_BASE_URL}{endpoint}", data=data, timeout=30
                )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": str(e)}

    @staticmethod
    def check_health() -> bool:
        """Check if backend API is available"""
        try:
            response = requests.get(f"{API_BASE_URL}/health", timeout=5)
            return response.status_code == 200
        except:
            return False


api_client = APIClient()

# ==================== CONFIGURATION ====================
st.set_page_config(
    page_title="CyberShield AI - Advanced Malware Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com",
        "Report a bug": "https://github.com",
        "About": "### CyberShield AI v2.0\nAdvanced AI-powered Malware Detection System",
    },
)

# ==================== CUSTOM CSS ====================
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    .main-header {
        font-size: 3.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
        padding: 0.5rem 0;
        text-shadow: 0 2px 10px rgba(102, 126, 234, 0.1);
    }
    
    .sub-header {
        font-size: 1.2rem;
        color: #6c757d;
        font-weight: 400;
        margin-bottom: 2rem;
    }
    
    .card-gradient {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 20px;
        padding: 25px;
        margin: 15px 0;
        color: white;
        box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        transition: all 0.3s ease;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .upload-zone {
        border: 4px dashed #667eea;
        border-radius: 20px;
        padding: 60px 40px;
        text-align: center;
        background: linear-gradient(135deg, rgba(102, 126, 234, 0.05) 0%, rgba(118, 75, 162, 0.05) 100%);
        transition: all 0.3s ease;
        cursor: pointer;
        margin: 20px 0;
    }
    
    .threat-badge {
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.9rem;
        display: inline-block;
        margin: 2px;
    }
    
    .severity-critical { background: linear-gradient(135deg, #FF416C 0%, #FF4B2B 100%); }
    .severity-high { background: linear-gradient(135deg, #FF9966 0%, #FF5E62 100%); }
    .severity-medium { background: linear-gradient(135deg, #FFD166 0%, #FF9E6D 100%); }
    .severity-low { background: linear-gradient(135deg, #06D6A0 0%, #1B9AAA 100%); }
    .severity-clean { background: linear-gradient(135deg, #4CC9F0 0%, #4361EE 100%); }
    
    .glass-effect {
        background: rgba(255, 255, 255, 0.95);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 15px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    }
    
    @media (prefers-color-scheme: dark) {
        .glass-effect {
            background: rgba(30, 30, 30, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
    }
</style>
""",
    unsafe_allow_html=True,
)


# ==================== HELPER FUNCTIONS ====================
def get_threat_level_color(threat_level: str) -> str:
    """Get color for threat level"""
    colors = {
        "CRITICAL": "#FF416C",
        "HIGH": "#FF5E62",
        "MEDIUM": "#FFD166",
        "LOW": "#06D6A0",
        "CLEAN": "#4CC9F0",
        "SAFE": "#4CC9F0",
        "LOW_RISK": "#06D6A0",
        "MEDIUM_RISK": "#FFD166",
        "HIGH_RISK": "#FF5E62",
        "CRITICAL_RISK": "#FF416C",
    }
    return colors.get(threat_level, "#667eea")


def create_threat_visualization(
    threat_level: str, score: float, confidence: float = 0.9
):
    """Create threat visualization gauge"""
    colors = {
        "CRITICAL": "#FF416C",
        "HIGH": "#FF5E62",
        "MEDIUM": "#FFD166",
        "LOW": "#06D6A0",
        "CLEAN": "#4CC9F0",
    }

    fig = go.Figure()

    fig.add_trace(
        go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": f"Threat Level: {threat_level}", "font": {"size": 20}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "darkblue"},
                "bar": {"color": colors.get(threat_level, "#667eea")},
                "bgcolor": "white",
                "borderwidth": 2,
                "bordercolor": "gray",
                "steps": [
                    {"range": [0, 20], "color": "#4CC9F0"},
                    {"range": [20, 40], "color": "#06D6A0"},
                    {"range": [40, 60], "color": "#FFD166"},
                    {"range": [60, 80], "color": "#FF5E62"},
                    {"range": [80, 100], "color": "#FF416C"},
                ],
            },
        )
    )

    fig.update_layout(
        height=300,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "darkblue", "family": "Inter"},
    )

    return fig


def create_metric_card(title: str, value: Any, delta: str = None, icon: str = "📊"):
    """Create a metric card"""
    col1, col2 = st.columns([1, 4])
    with col1:
        st.markdown(
            f"<h1 style='font-size: 2.5rem; margin: 0;'>{icon}</h1>",
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"<h3 style='margin: 0; color: #6c757d;'>{title}</h3>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<h2 style='margin: 0; font-weight: 700;'>{value}</h2>",
            unsafe_allow_html=True,
        )
        if delta:
            st.markdown(
                f"<p style='margin: 0; color: #28a745;'>{delta}</p>",
                unsafe_allow_html=True,
            )


# ==================== MAIN APPLICATION ====================
def main():
    """Main Streamlit application"""

    # Initialize session state
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []

    # Header
    col1, col2, col3 = st.columns([1, 3, 1])
    with col2:
        st.markdown(
            '<div class="main-header">🛡️ CyberShield AI</div>', unsafe_allow_html=True
        )
        st.markdown(
            '<div class="sub-header">Advanced AI-Powered Malware Detection & Website Security Scanner</div>',
            unsafe_allow_html=True,
        )

    # Check API health
    api_available = api_client.check_health()
    if not api_available:
        st.warning(
            "⚠️ Backend API is not available. Please ensure the backend server is running on http://localhost:8000"
        )

    # Navigation sidebar
    with st.sidebar:
        st.image(
            "https://img.icons8.com/color/96/000000/security-shield-green.png",
            width=100,
        )

        selected = st.radio(
            "Navigation",
            ["🏠 Dashboard", "📁 File Scanner", "🌐 Website Scanner", "⚙️ Settings"],
            label_visibility="collapsed",
        )

        st.markdown("---")

        # Quick stats
        st.subheader("⚡ Quick Stats")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Files Scanned", len(st.session_state.scan_history))
        with col2:
            st.metric(
                "Threats Found",
                sum(
                    1
                    for s in st.session_state.scan_history
                    if s.get("threat_level") in ["CRITICAL", "HIGH"]
                ),
            )

        st.markdown("---")

        # API Status
        st.subheader("🔧 System Status")
        status_cols = st.columns(2)
        with status_cols[0]:
            st.success("✅ API" if api_available else "❌ API")
        with status_cols[1]:
            st.success("✅ Frontend")

        st.markdown("---")

        if st.button("🔄 Refresh System", use_container_width=True):
            st.rerun()

    # Dashboard Page
    if selected == "🏠 Dashboard":
        st.header("📊 Security Dashboard")

        # Top metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            create_metric_card(
                "Total Scans", len(st.session_state.scan_history), "+12%", "🔍"
            )
        with col2:
            create_metric_card(
                "Threats Detected",
                sum(
                    1
                    for s in st.session_state.scan_history
                    if s.get("threat_level") in ["CRITICAL", "HIGH"]
                ),
                "-5%",
                "⚠️",
            )
        with col3:
            create_metric_card(
                "API Status", "Online" if api_available else "Offline", "+2.1%", "🎯"
            )
        with col4:
            create_metric_card("Response Time", "2.3s", "-0.4s", "⚡")

        st.markdown("---")

        # Charts
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Threat Distribution")
            threat_data = pd.DataFrame(
                {
                    "Threat Type": [
                        "Ransomware",
                        "Trojans",
                        "Spyware",
                        "Adware",
                        "Viruses",
                    ],
                    "Count": [23, 34, 12, 18, 15],
                }
            )
            fig = px.pie(
                threat_data,
                values="Count",
                names="Threat Type",
                color_discrete_sequence=px.colors.sequential.RdBu,
            )
            fig.update_traces(textposition="inside", textinfo="percent+label")
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("Recent Activity")
            activity_data = pd.DataFrame(
                {
                    "Time": pd.date_range("2024-01-01", periods=10, freq="H"),
                    "Activity": [
                        "File Scan",
                        "URL Scan",
                        "Threat Blocked",
                        "System Update",
                        "Model Training",
                        "Backup",
                        "Scan Complete",
                        "Alert",
                        "Report Generated",
                        "API Call",
                    ],
                }
            )
            fig = px.scatter(
                activity_data,
                x="Time",
                y="Activity",
                size=[10, 15, 20, 10, 15, 10, 15, 20, 10, 15],
                color="Activity",
                size_max=20,
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

        # Recent scans
        if st.session_state.scan_history:
            st.subheader("📜 Recent Scans")
            for scan in st.session_state.scan_history[-5:]:
                color = get_threat_level_color(scan.get("threat_level", "CLEAN"))
                st.markdown(
                    f"""
                <div class="glass-effect" style="padding: 15px; margin: 10px 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span><strong>{scan.get('type', 'Unknown')}:</strong> {scan.get('target', 'Unknown')}</span>
                        <span style="background: {color}; color: white; padding: 4px 12px; border-radius: 15px; font-size: 0.8rem;">
                            {scan.get('threat_level', 'Unknown')}
                        </span>
                    </div>
                </div>
                """,
                    unsafe_allow_html=True,
                )

    # File Scanner
    elif selected == "📁 File Scanner":
        st.header("🔬 File Scanner")

        st.markdown(
            """
        <div class="upload-zone">
            <h3 style="margin-bottom: 10px;">📁 Drag & Drop Files Here</h3>
            <p style="color: #6c757d; margin-bottom: 20px;">Or click to browse files (Max 100MB)</p>
        </div>
        """,
            unsafe_allow_html=True,
        )

        uploaded_file = st.file_uploader(
            "Choose files",
            type=[
                "exe",
                "dll",
                "js",
                "php",
                "py",
                "bat",
                "ps1",
                "vbs",
                "zip",
                "rar",
                "7z",
                "pdf",
                "doc",
                "docx",
                "xls",
                "xlsx",
            ],
            label_visibility="collapsed",
            accept_multiple_files=False,
        )

        if uploaded_file:
            # File info
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.info(f"**File:** {uploaded_file.name}")
            with col2:
                st.info(f"**Size:** {uploaded_file.size / 1024:.1f} KB")
            with col3:
                st.info(f"**Type:** {uploaded_file.type}")
            with col4:
                file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()[:16]
                st.info(f"**Hash:** {file_hash}...")

            # Start scan button
            if st.button("🚀 Start Analysis", type="primary", use_container_width=True):
                if not api_available:
                    st.error(
                        "Backend API is not available. Please start the backend server."
                    )
                else:
                    with st.spinner("Scanning file..."):
                        try:
                            # Upload file to backend
                            files = {
                                "file": (
                                    uploaded_file.name,
                                    uploaded_file.getvalue(),
                                    uploaded_file.type,
                                )
                            }
                            # ✅ CORRECT: File endpoint is "/api/v1/scan/file"
                            result = api_client.post("/api/v1/scan/file", files=files)

                            if "error" in result:
                                st.error(f"Scan failed: {result['error']}")
                            else:
                                st.success("✅ Analysis Complete!")

                                # Get results
                                scan_id = result.get("scan_id", "N/A")
                                filename = result.get("filename", "Unknown")

                                # Display results based on response structure
                                st.subheader("📊 Scan Results")

                                # Create a threat level from results
                                threat_level = "CLEAN"
                                score = 0

                                # Try to get threat info from results
                                if isinstance(result, dict):
                                    results_data = result.get("results", {})
                                    if isinstance(results_data, dict):
                                        threat_level = results_data.get(
                                            "threat_level", "CLEAN"
                                        )
                                        score = results_data.get("score", 50)

                                # Display threat visualization
                                col1, col2 = st.columns([2, 1])
                                with col1:
                                    fig = create_threat_visualization(
                                        threat_level, score
                                    )
                                    st.plotly_chart(fig, use_container_width=True)

                                with col2:
                                    color = get_threat_level_color(threat_level)
                                    st.markdown(
                                        f"""
                                    <div style="text-align: center; padding: 20px;">
                                        <div style="font-size: 3rem; margin-bottom: 10px;">
                                            {"🛡️" if threat_level in ['CLEAN', 'LOW', 'SAFE'] else "⚠️"}
                                        </div>
                                        <h2 style="color: {color}; margin: 0;">{threat_level}</h2>
                                    </div>
                                    """,
                                        unsafe_allow_html=True,
                                    )

                                # Show results JSON
                                with st.expander("📋 Detailed Results"):
                                    st.json(result)

                                # Save to history
                                scan_data = {
                                    "timestamp": datetime.now(),
                                    "type": "File",
                                    "target": filename,
                                    "threat_level": threat_level,
                                    "score": score,
                                }
                                st.session_state.scan_history.append(scan_data)

                        except Exception as e:
                            st.error(f"Scan failed: {e}")

    # Website Scanner
    elif selected == "🌐 Website Scanner":
        st.header("🌐 Website Security Scanner")

        col1, col2 = st.columns([3, 1])
        with col1:
            url = st.text_input(
                "Enter website URL",
                placeholder="https://example.com",
                help="Include http:// or https://",
            )

        with col2:
            st.write("")
            st.write("")
            scan_btn = st.button(
                "🔍 Scan Website", type="primary", use_container_width=True
            )

        if scan_btn and url:
            if not api_available:
                st.error(
                    "Backend API is not available. Please start the backend server."
                )
            else:
                with st.spinner(f"Scanning {url}..."):
                    try:
                        # ✅ FIXED: Changed from data= to json= for Pydantic model
                        result = api_client.post("/api/v1/scan/url", json={"url": url})

                        if "error" in result:
                            st.error(f"Scan failed: {result['error']}")
                        else:
                            st.success("✅ Scan Complete!")

                            # Display results
                            st.subheader("📊 Scan Results")

                            # Get values from result
                            scan_results = result.get("results", {})
                            threat_level = scan_results.get("threat_level", "SAFE")
                            final_score = scan_results.get("score", 100)

                            # Overall score
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Security Score", f"{final_score}/100")
                            with col2:
                                st.metric("Threat Level", threat_level)
                            with col3:
                                st.metric("Status", "Completed")

                            # Threat visualization
                            col1, col2 = st.columns([2, 1])
                            with col1:
                                fig = create_threat_visualization(
                                    threat_level, final_score
                                )
                                st.plotly_chart(fig, use_container_width=True)

                            with col2:
                                color = get_threat_level_color(threat_level)
                                st.markdown(
                                    f"""
                                    <div style="text-align: center; padding: 20px;">
                                        <div style="font-size: 3rem; margin-bottom: 10px;">
                                            {"🛡️" if threat_level in ['CLEAN', 'LOW', 'SAFE'] else "⚠️"}
                                        </div>
                                        <h2 style="color: {color}; margin: 0;">{threat_level}</h2>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )

                            # Display results
                            with st.expander("📋 Detailed Results"):
                                st.json(result)

                            # Save to history
                            scan_data = {
                                "timestamp": datetime.now(),
                                "type": "Website",
                                "target": url,
                                "threat_level": threat_level,
                                "score": final_score,
                                "scan_id": result.get("scan_id", ""),
                            }
                            st.session_state.scan_history.append(scan_data)

                    except Exception as e:
                        st.error(f"Scan failed: {e}")

    # Settings
    elif selected == "⚙️ Settings":
        st.header("⚙️ System Settings")

        tabs = st.tabs(["API Configuration", "System Info"])

        with tabs[0]:
            st.subheader("API Configuration")
            st.write(f"Backend API URL: `{API_BASE_URL}`")

            if st.button("🔄 Test API Connection"):
                if api_available:
                    st.success("✅ API is available!")
                    health = api_client.get("/health")
                    st.json(health)
                else:
                    st.error(
                        "❌ API is not available. Please check the backend server."
                    )

            # Add API debugging section
            with st.expander("🔍 API Debug"):
                st.write("Test endpoints manually:")

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Test /health"):
                        try:
                            response = requests.get(f"{API_BASE_URL}/health", timeout=5)
                            st.write(f"Status: {response.status_code}")
                            st.write(f"Response: {response.json()}")
                        except Exception as e:
                            st.error(f"Error: {e}")

                with col2:
                    if st.button("Test /scan/url"):
                        try:
                            response = requests.post(
                                f"{API_BASE_URL}/api/v1/scan/url",
                                json={"url": "https://example.com"},
                                timeout=10,
                            )
                            st.write(f"Status: {response.status_code}")
                            st.write(f"Response: {response.json()}")
                        except Exception as e:
                            st.error(f"Error: {e}")

        with tabs[1]:
            st.subheader("System Information")
            sys_info = {
                "Version": "CyberShield AI v2.0",
                "Frontend": "Streamlit",
                "Backend": "FastAPI" if api_available else "Unknown",
                "API Status": "Online" if api_available else "Offline",
                "Python Version": "3.9+",
            }

            for key, value in sys_info.items():
                col1, col2 = st.columns([1, 3])
                with col1:
                    st.write(f"**{key}:**")
                with col2:
                    st.write(value)


if __name__ == "__main__":
    main()
