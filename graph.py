# graph.py
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Plot style
sns.set_theme(style="whitegrid")
plt.rcParams['figure.figsize'] = (12, 6)

# Global base dataset path
BASE_DATA_PATH = r"P:\SSM project\Models\Models_PKL\SSH\df_ssh.csv"

def plot_ssh_anomaly_overlay(user_df):

    df = pd.read_csv(BASE_DATA_PATH)

    # Start plot
    fig, ax = plt.subplots()

    # Plot original anomalies and normal traffic
    sns.histplot(df[df['iso_label'] == -1]['hour'], color='red', label='Anomaly', kde=True, stat='count', ax=ax)
    sns.histplot(df[df['iso_label'] == 1].sample(frac=0.3, random_state=42)['hour'], color='green', label='Normal', kde=True, stat='count', ax=ax, alpha=0.6)


    # Derive 'hour' from timestamp if needed
    if 'hour' not in user_df.columns:
        user_df['hour'] = pd.to_datetime(user_df['timestamp']).dt.hour

    # Plot user-uploaded data in blue
    sns.histplot(user_df['hour'], color='blue', label='User Data', kde=True, stat='count', alpha=0.5, ax=ax)

    # Titles and layout
    ax.set_title("Anomaly vs Normal Activity by Hour", fontsize=16)
    ax.set_xlabel("Hour of Day")
    ax.set_ylabel("count")
    ax.legend()
    plt.tight_layout()

    return fig
