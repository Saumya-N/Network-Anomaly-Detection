import pandas as pd
import streamlit as st

# Reports Page


def reports_page():
    st.title('Reports')
    st.write('This page displays KPI metrics and charts based on the KDD Network Anomaly Dataset.')

    # Load dataset (you might need to adjust the path)
    data = pd.read_csv('Network_anomaly_data.csv')

    # KPI Metrics
    st.header('KPI Metrics')

    # Example KPI metrics
    num_records = len(data)
    num_attacks = len(data[data['attack'] != 'normal'])
    attack_percentage = (num_attacks / num_records) * 100

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Connections", num_records)
    with col2:
        st.metric("Total Attacks", num_attacks)
    with col3:
        st.metric("Percentage of Attacks", f"{attack_percentage:.2f}%")

    # Example Charts
    st.header('Charts')

    # Attack types distribution
    attack_types = sorted(data['attack_type'].value_counts())
    st.subheader('Distribution of Attack Types')
    st.bar_chart(attack_types)

    # Plotting with matplotlib
    st.subheader('Distribution of Protocol Types')
    protocol_counts = sorted(data['protocoltype'].value_counts())
    st.bar_chart(protocol_counts)

    # Show example of time-series or other metrics if applicable
    # More complex visualizations can be added as needed

    st.image('bkg.jpg')
