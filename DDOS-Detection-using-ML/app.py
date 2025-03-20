import pandas as pd
import numpy as np
import streamlit as st
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import silhouette_score

def preprocess_data():
    # Load data
    df = pd.read_csv(r"G:\Sem 4\Project\DDoS-attack-detection-using-HTTP-packet-clustering-pattern-master\WP_Dataset\wplogs.csv")

    # Preprocessing
    df['@timestamp'] = pd.to_datetime(df['@timestamp'], format='%b %d, %Y @ %H:%M:%S.%f')
    df['@timestamp.1'] = pd.to_datetime(df['@timestamp.1'], format='%b %d, %Y @ %H:%M:%S.%f')
    df['@timestamp'] = pd.to_datetime(df['@timestamp'])
    df['@timestamp.1'] = pd.to_datetime(df['@timestamp.1'])
    df['bytes'] = pd.to_numeric(df['bytes'], errors='ignore')
    df.dropna(subset=['httpversion', 'request', 'verb'], inplace=True)
    df = df[df['clientip'] != '127.0.0.1']
    df['geoip.country_code3'].fillna('unknown', inplace=True)

    # One-hot encoding
    categorical_cols = ['useragent.device', 'useragent.name', 'useragent.os', 'verb', 'useragent.os_name']
    encoder = OneHotEncoder(sparse=False, handle_unknown='ignore')
    encoded_cols = pd.DataFrame(encoder.fit_transform(df[categorical_cols]))
    encoded_cols.columns = encoder.get_feature_names_out(categorical_cols)
    df.drop(categorical_cols, axis=1, inplace=True)
    df = pd.concat([df, encoded_cols], axis=1)

    return df

st.title("Data Preprocessing App")

# Button to preprocess data
if st.button("Preprocess Data"):
    st.write("Processing data...")
    df_processed = preprocess_data()
    st.write("Data processing complete!")
    st.write(df_processed.head())
import pandas as pd
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import streamlit as st
import matplotlib.dates as mdates

def perform_clustering(df):
    # Drop rows with missing values in 'response' and 'bytes' columns
    df.dropna(subset=['response', 'bytes'], inplace=True)
    
    # Convert columns to appropriate data types
    df['@timestamp'] = pd.to_datetime(df['@timestamp'], format='%b %d, %Y @ %H:%M:%S.%f', errors='coerce')
    df['@timestamp.1'] = pd.to_datetime(df['@timestamp.1'], format='%b %d, %Y @ %H:%M:%S.%f', errors='coerce')
    df['bytes'] = df['bytes'].str.replace(',', '').astype(float)
    
    # Remove rows with NaT (not a time) values
    df.dropna(subset=['@timestamp', '@timestamp.1'], inplace=True)
    
    # Extract features for clustering
    X = df[['response', 'bytes']]
    
    # Perform K-means clustering
    kmeans = KMeans(n_clusters=2)  
    kmeans.fit(X)

    # Calculate Silhouette Score
    silhouette_avg = silhouette_score(X, kmeans.labels_)
    st.write("Silhouette Score:", silhouette_avg)
    
    # Assign cluster labels to the dataframe
    df['cluster'] = kmeans.labels_
    
    return df

def detect_ddos(df, threshold_per_byte=1000):
    timestamp_data = []
    distinct_ips = set()

    cluster_0_ips = df[df['cluster'] == 0]['clientip'].unique()

    for ip in cluster_0_ips:
        ip_data = df[df['clientip'] == ip]
        for _, row in ip_data.iterrows():
            bytes_transfer = int(row['bytes'])
            if bytes_transfer >= threshold_per_byte:
                timestamp_data.append({
                    'clientip': ip,
                    '@timestamp': row['@timestamp'],
                    'bytes': bytes_transfer
                })
                distinct_ips.add(ip)

    ip_frequency = df['clientip'].value_counts()
    max_frequency_ips = ip_frequency[ip_frequency == ip_frequency.max()].index

    filtered_timestamp_data = []
    for data in timestamp_data:
        if data['clientip'] in max_frequency_ips:
            filtered_timestamp_data.append(data)

    timestamp_df = pd.DataFrame(filtered_timestamp_data)
    
    return max_frequency_ips, timestamp_df

# Load your dataset here
df = pd.read_csv(r"G:\Sem 4\Project\DDoS-attack-detection-using-HTTP-packet-clustering-pattern-master\WP_Dataset\wplogs.csv")

st.title("DDoS Detection App")

# Button to perform clustering
if st.button("Perform Clustering"):
    st.write("Performing clustering...")
    df_clustered = perform_clustering(df.copy())
    st.write("Clustering completed!")

    # Plot the clusters
    plt.figure(figsize=(10, 6))
    plt.scatter(df_clustered['response'], df_clustered['bytes'], c=df_clustered['cluster'], cmap='viridis')
    plt.title('K-means Clustering of Response vs Bytes')
    plt.xlabel('Response')
    plt.ylabel('Bytes')
    plt.colorbar(label='Cluster')
    st.pyplot(plt)


# Button to perform clustering and detect DDoS attacks
if st.button("Detect DDoS Attacks"):
    st.write("Performing clustering...")
    df_clustered = perform_clustering(df.copy())
    st.write("Clustering completed!")
    
    st.write("Detecting DDoS attacks...")
    max_frequency_ips, timestamp_df = detect_ddos(df_clustered)
    st.write("DDoS detection completed!")
    
    st.write("IP addresses with potential DDoS Attack:")
    st.write(list(max_frequency_ips))
    
    st.write("Timestamp Data:")
    st.write(timestamp_df)

    # Plotting the attack phase graph
    st.write("Plotting attack phase graph...")
    timestamp_df['@timestamp'] = pd.to_datetime(timestamp_df['@timestamp'])
    fig, ax = plt.subplots(figsize=(15, 8))

    for ip in set(timestamp_df['clientip']):
        ip_data = timestamp_df[timestamp_df['clientip'] == ip]
        ax.plot(ip_data['@timestamp'], ip_data['bytes'], label=ip)

    ax.set_title('Attack phase of the Ip-address')
    ax.set_xlabel('Timestamp')
    ax.set_ylabel('Bytes Transferred')
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))

    plt.xticks(rotation=45)
    plt.tight_layout()
    st.pyplot(fig)


