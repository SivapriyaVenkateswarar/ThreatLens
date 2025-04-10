import streamlit as st
import pandas as pd
import joblib
import plotly.express as px
import sys
import os

sys.path.append(r"P:\SSM project\Dashboard\graph.py")

from graph import plot_ssh_anomaly_overlay
import matplotlib.pyplot as plt  
model = joblib.load(r"P:\SSM project\Models\Models_PKL\system_intrusion.pkl")

sys.path.append(r"P:\SSM project\preprocessing")

from pre_processing import preprocess_intrusion
from pre_processing import preprocess_phishing
from pre_processing import preprocess_ssh
from pre_processing import preprocess_server_logs

st.set_page_config(page_title="AI Security Dashboard", layout="wide", page_icon="🔐")

st.markdown("""
    <style>
        .card-style {
            background-color: #eef6fb;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
            margin-bottom: 20px;
        }
        .card-title {
            font-size: 22px;
            font-weight: bold;
            color: #1a4c8b;
            margin-bottom: 10px;
        }
        .upload-box {
            border: 2px dashed #66aaff;
            border-radius: 10px;
            padding: 20px;
            background-color: #f7fbff;
            margin-bottom: 10px;
        }
    </style>
""", unsafe_allow_html=True)

# Page Title
st.title("🔐 ThreatLens")

col1, col2 = st.columns([1.7, 1.8])

with col1:
    with st.container():
        st.markdown('''
            <div style="
                background-color: #eaf3fb;
                padding: 25px 30px;
                border-radius: 16px;
                box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.05);
                margin-bottom: 20px;
            ">
                <h4 style="color: #1a4c8b; font-weight: 700;"> 🔍 System Intrusion Detection</h4>
        ''', unsafe_allow_html=True)

        uploaded_file = st.file_uploader("Upload CSV", type=["csv"], key="sys_intrusion_csv")
        detect_button = st.button("Detect Threats", key="sys_intrusion_button")

        if uploaded_file is not None and detect_button:
            try:
                df = pd.read_csv(uploaded_file)
                df_clean_scaled, valid_indices = preprocess_intrusion(df.copy())
                preds = model.predict(df_clean_scaled)
                df.loc[valid_indices, 'Prediction'] = preds

                st.success("Prediction complete!")
                st.write("Sample Output:")
                st.dataframe(df.head())

            except Exception as e:
                st.error(f"❌ Error during processing: {e}")
        st.markdown("</div>", unsafe_allow_html=True)

sys.path.append(r"P:\SSM project\Models\Models_PKL\incident_log")        
from recommender import recommend_resolution

with col2:
    with st.container():
        st.markdown('''
            <div style="
                background-color: #eaf3fb;
                padding: 25px 30px;
                border-radius: 16px;
                box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.05);
                margin-bottom: 20px;
            ">
                <h4 style="color: #1a4c8b; font-weight: 700;">💡 Symptom-Based Resolution Recommender</div>
        ''', unsafe_allow_html=True)

        user_query = st.text_input("Describe the issue (e.g., VPN not working remotely):")
        if st.button("Get Recommendations"):
            if user_query:
                try:
                    recs,top_matches = recommend_resolution(user_query)

                    st.success("✅ Recommendations:")
                    st.write(recs)

                    st.markdown("**Similar Past Incidents:**")
                    st.dataframe(top_matches)

                except Exception as e:
                    st.error(f"❌ Error in generating recommendation: {e}")
            else:
                st.warning("Please enter a query.")
        st.markdown("</div>", unsafe_allow_html=True)

model = joblib.load(r"P:\SSM project\Models\Models_PKL\system_intrusion.pkl")

col3, col4 = st.columns([1.1, 2.6])
model_1 = joblib.load(r"P:\SSM project\Models\Models_PKL\phishing.pkl")

with col3:
    with st.container():
        st.markdown('''
            <div style="
                background-color: #eaf3fb;
                padding: 25px 30px;
                border-radius: 16px;
                box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.05);
                margin-bottom: 20px;
            ">
                <h4 style="color: #1a4c8b; font-weight: 700;"> 🔍 Phishing URL Detection</h4>
        ''', unsafe_allow_html=True)

        uploaded_file = st.file_uploader("Upload CSV", type=["csv"], key="phishing_detect_csv")
        detect_button = st.button("Predict", key="phishing_detect_button")

        if uploaded_file is not None and detect_button:
            try:
                df = pd.read_csv(uploaded_file)
                df_clean = preprocess_phishing(df.copy())
                preds = model_1.predict(df_clean)
                df['Prediction'] = preds

                st.success("Prediction complete!")
                st.write("Sample Output:")
                st.dataframe(df.head())

            except Exception as e:
                st.error(f"❌ Error during processing: {e}")
        st.markdown("</div>", unsafe_allow_html=True)

model_2 = joblib.load(r"P:\SSM project\Models\Models_PKL\SSH.pkl")

with col4:
    with st.container():
        st.markdown('''
            <div style="
                background-color: #eaf3fb;
                padding: 25px 30px;
                border-radius: 16px;
                box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.05);
                margin-bottom: 20px;
            ">
                <h4 style="color: #1a4c8b; font-weight: 700;">🛡️ SSH Anomaly Detection</h4>
        ''', unsafe_allow_html=True)

        uploaded_file = st.file_uploader("Upload SSH Log CSV", type=["csv"], key="SSH_anomaly_csv")
        detect_button = st.button("Detect Anomalies", key="anomaly_detect_button")

        if uploaded_file is not None and detect_button:
            try:
                df = pd.read_csv(uploaded_file)
                df_clean = preprocess_ssh(df.copy())
                preds = model_2.predict(df_clean)
                df['Prediction'] = preds

                st.success("✅ SSH anomaly prediction complete!")
                st.write("Sample Output:")
                st.dataframe(df.head())

                st.markdown("#### 📈 Anomaly Visualization (Hour of Day)")
                fig = plot_ssh_anomaly_overlay(df_clean)
                st.pyplot(fig)

            except Exception as e:
                st.error(f"❌ Error during processing: {e}")

        st.markdown("</div>", unsafe_allow_html=True)

sys.path.append(r"P:\SSM project\Dashboard\make_graph.py ")
from make_graph  import make_network_graph 
from make_graph  import make_protocol_graphs 
model_3 = joblib.load(r"P:\SSM project\Models\Models_PKL\server_logs.pkl")

col5, = st.columns([3.6])
with col5:
    with st.container():
        st.markdown('''
            <div style="background-color: #eaf3fb; padding: 25px 30px; border-radius: 16px;
                box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.05); margin-bottom: 20px;">
                <h4 style="color: #1a4c8b; font-weight: 700;">🌐 Server Log Network Graph</h4>
        ''', unsafe_allow_html=True)

        uploaded_network_csv = st.file_uploader("Upload Network Logs CSV", type=["csv"], key="server_network_csv")
        detect_button = st.button("Detect server log", key="server_detect_button")

        if uploaded_network_csv:
            try:
                df_net = pd.read_csv(uploaded_network_csv)
                df_net = preprocess_server_logs(df_net)

                preds = model_3.predict(df_net)
                df_net['Prediction'] = preds

                st.success("Sever detected!")
                st.write("Sample Output:")
                st.dataframe(df_net.head())
                required_cols = ['Src IP Addr', 'Dst IP Addr', 'Proto', 'Bytes', 'Packets', 'Flags', 'Duration']
                if all(col in df_net.columns for col in required_cols):
                    
                    graph_type = st.radio("Choose Graph Type", ["Weighted Graph", "Protocol-wise Graph"])

                    if graph_type == "Weighted Graph":
                        img_buf = make_network_graph(df_net)
                        st.image(img_buf, caption="Weighted Directed Network Graph", use_container_width=True)

                    elif graph_type == "Protocol-wise Graph":
                        graph_list = make_protocol_graphs(df_net)
                        for proto, buf in graph_list:
                            st.image(buf, caption=f"Protocol {proto} - Top 100 Connections", use_container_width=True)

                else:
                    st.error("Uploaded CSV does not have required columns.")
            except Exception as e:
                st.error(f"❌ Error processing network graph: {e}")

        st.markdown("</div>", unsafe_allow_html=True)

