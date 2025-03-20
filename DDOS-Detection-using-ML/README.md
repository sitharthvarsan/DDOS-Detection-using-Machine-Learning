# DDoS Attack Detection Using K-Means Clustering

This project implements a DDoS (Distributed Denial of Service) attack detection system using machine learning techniques, specifically leveraging K-means clustering. The primary aim is to identify potential DDoS attacks in real time by analyzing network traffic patterns.

## Objective

The goal of this project is to develop an effective and efficient DDoS attack detection model that can recognize unusual network activity indicative of a DDoS attack. This is achieved by clustering network data and assessing the clustering quality using the silhouette score.

## Methodology

1. **Data Collection:**  
   Network traffic data is collected from various sources, including simulated DDoS attack scenarios.

2. **Feature Extraction:**  
   Relevant features are extracted from the network data to facilitate clustering.

3. **K-Means Clustering:**  
   The K-means algorithm is applied to cluster the network traffic into normal and potentially malicious categories.

4. **Silhouette Score Evaluation:**  
   The silhouette score is used to evaluate the quality of the clustering and determine the optimal number of clusters.

## Results and Evaluation

The model successfully identifies periods of potential DDoS attacks by detecting clusters of unusual network activity. The silhouette score provides a metric for evaluating the model's effectiveness in distinguishing between normal and anomalous traffic.

## Installation and Usage

### Prerequisites

- Python 3.x
- Required libraries: NumPy, Pandas, Scikit-learn, Matplotlib

