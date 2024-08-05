# Cybersecurity

## Problem Statement

Network Anomaly Detection is one of the most important and an ever evolving field in the domain of cybersecurity. With the improvisation of existing methodologies and the advent of new ones for identifying and mitigating cyber risk, the advancement in threats have also increased. 
The task at hand is to have a detailed understanding of the domain and to identify the areas of cybersecurity where one can leverage the capabilities of the various available machine learning algorithms like supervised, unsupervised and deep learning and to combine them together to identify existing and new threats with high precision and in time.

## About the Dataset:

The KDD Network Anomaly dataset is used for this project. 

Attack Column:
The attacks listed in the provided data correspond to several categories of common cyberattacks. The list of attack types mentioned can be categorized into four main categories of cyberattacks:

1. Denial-of-Service (s) Attacks
2. Probe Attacks
3. Remote-to-Local (R2L) Attacks
4. User-to-Root (U2R) Attacks

This categorization helps in understanding the nature of each attack type and assists in developing appropriate detection and mitigation strategies for network security.
 
## Preprocessing

The data preprocessing steps involve cleaning, encoding and resampling the data, and feature engineering.

## Modeling

Machine learning models like Random Forest Classifier (RFC) and XGBoost for detecting anomalies were used. The model selection was based on their performance in classifying normal and various anomalous network traffic.

## Results

The results showed high accuracy in detecting network anomalies. The models successfully identified different types of attacks with significant precision and recall metrics.

## [Dashboard](https://public.tableau.com/views/NetworkAnomalyDetection/OverallAnalysis?:language=en-GB&:sid=&:redirect=auth&:display_count=n&:origin=viz_share_link)

The project includes a Tableau dashboard to visualize network traffic and anomalies. Key components of the dashboard include:

- Anomaly Detection Summary
- Top Threats Watch
 
The dashboard provides insights into network behavior and helps in monitoring for potential security threats.

## App Functionality

The [Streamlit app](https://securenetai.streamlit.app/) offers:

- Login Page:
	- Username: user
	- Password: Pass
- Home Page: Overview of the app and its features.
- Prediction Page: Allows users to input network traffic data and predict potential anomalies.
- Reports Page: Users can view key performance metrics and download dataset and reports in CSV and PPT formats respectively.
The report functionality is particularly helpful for users to analyze trends and patterns in network traffic and to generate comprehensive reports for further analysis.

## Challenges

During the project, we faced challenges such as data imbalance, feature selection, and optimizing model performance. These were addressed through techniques like SMOTE for oversampling, feature engineering, and hyperparameter tuning using MLFlow for efficient tracking.
