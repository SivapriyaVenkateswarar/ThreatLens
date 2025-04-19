import streamlit as st
import faiss
import joblib
from sentence_transformers import SentenceTransformer
import numpy as np
import pandas as pd

@st.cache_resource
def load_model():
    return SentenceTransformer('all-MiniLM-L6-v2')

@st.cache_resource
def load_data():
    df = joblib.load(r"P:\SSM project\Models\Models_PKL\incident_log\incident_data.pkl")
    return df

@st.cache_resource
def load_faiss_index():
    return faiss.read_index(r"P:\SSM project\Models\Models_PKL\incident_log\symptom_index.faiss")

model = load_model()
df_unique = load_data()
index = load_faiss_index()

def recommend_resolution(query_text, top_k=5):
    query_vec = model.encode([query_text]).astype("float32")
    D, I = index.search(query_vec, top_k)
    valid_indices = I[0][I[0] != -1]
    if len(valid_indices) == 0:
        return {
            "Most Likely Closed Code": "No Match",
            "Suggested Assignment Group": "No Match",
            "Suggested Resolver": "No Match"
        }

    similar_incidents = df_unique.iloc[valid_indices]

    def safe_mode(series):
        return series.mode().values[0] if not series.mode().empty else "Not Available"

    recommendations = {
        "Most Likely Closed Code": safe_mode(similar_incidents['closed_code']),
        "Suggested Assignment Group": safe_mode(similar_incidents['assignment_group']),
        "Suggested Resolver": safe_mode(similar_incidents['resolved_by'])
    }

    top_similar = similar_incidents[['u_symptom', 'resolution_time_minutes', 'priority']]

    return recommendations, top_similar
