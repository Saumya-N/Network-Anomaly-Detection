import streamlit as st
import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import LabelEncoder

# Load model
with open('model/model.pkl', 'rb') as f:
    model, scaler = pickle.load(f)


def detection_page():
    st.image('bkg.png', use_column_width=True)

    # Title of the app
    st.title('Network Anomaly Detection')

    # Create a 4-column layout
    col1, col2, col3, col4 = st.columns(4)

    # Input File
    uploaded_file = st.sidebar.file_uploader("Upload your network traffic data")

    if uploaded_file:
        data = pd.read_csv(uploaded_file)

        # Label Encoding
        cat_cols = ['protocoltype', 'service', 'flag']
        for col in cat_cols:
            le = LabelEncoder()
            data[col] = le.fit_transform(data[col])

        if st.button('Scan'):
            columns = data.columns
            data = scaler.transform(data)
            data = pd.DataFrame(data, columns=columns)

            # Make a prediction
            prediction = model.predict(data)

            # Calculate Probability
            probas = model.predict_proba(data)

            if prediction == 'DoS':
                prob = np.round(probas[:, 0][0] * 100)
            elif prediction == 'Probe':
                prob = np.round(probas[:, 1][0] * 100)
            elif prediction == 'R2L':
                prob = np.round(probas[:, 2][0] * 100)
            elif prediction == 'U2R':
                prob = np.round(probas[:, 3][0] * 100)
            else:
                prob = np.round(probas[:, 4][0] * 100)

            # Display the prediction
            prediction_text = (
                f'Alert: There is a {prob}% chance that you are currently experiencing a Denial of Service(DoS) attack.'
                'Immediate action is required to mitigate the impact.'
                if prediction == 0 else
                f'Alert: There is a {prob}% chance that suspicious PROBING activity is occurring.'
                'Potential reconnaissance in progress.'
                if prediction == 1 else
                f'Alert: There is a {prob}% probability that a REMOTE-TO-LOCAL attack is underway.'
                'Unauthorized remote access attempt identified.'
                if prediction == 2 else
                f'Alert: There is a {prob}% chance that a USER-TO-ROOT attack is happening.'
                'Suspicious privilege escalation detected.'
                if prediction == 3 else
                f'You are SAFE! No anomalies or security threats detected with {prob}% certainty.'
            )

            # Display the prediction with fancy formatting
            st.markdown(
                f"<h4>{prediction_text}</h4>",
                unsafe_allow_html=True
            )

    else:
        # Input form
        with col1:
            protocoltype_i = st.selectbox('Protocol Type', ['tcp', 'udp', 'icmp'])
            service_i = st.selectbox('Service', [
                'ftp_data', 'other', 'private', 'http', 'remote_job', 'name', 'netbios_ns',
                'eco_i', 'mtp', 'telnet', 'finger', 'domain_u', 'supdup', 'uucp_path',
                'Z39_50', 'smtp', 'csnet_ns', 'uucp', 'netbios_dgm', 'urp_i', 'auth',
                'domain', 'ftp', 'bgp', 'ldap', 'ecr_i', 'gopher', 'vmnet', 'systat',
                'http_443', 'efs', 'whois', 'imap4', 'iso_tsap', 'echo', 'klogin', 'link',
                'sunrpc', 'login', 'kshell', 'sql_net', 'time', 'hostnames', 'exec',
                'ntp_u', 'discard', 'nntp', 'courier', 'ctf', 'ssh', 'daytime', 'shell',
                'netstat', 'pop_3', 'nnsp', 'IRC', 'pop_2', 'printer', 'tim_i', 'pm_dump',
                'red_i', 'netbios_ssn', 'rje', 'X11', 'urh_i', 'http_8001', 'aol',
                'http_2784', 'tftp_u', 'harvest'
            ])
            flag_i = st.selectbox('Flag', ['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'RSTOS0', 'S3', 'S2', 'OTH'])
            srcbytes = st.number_input('Source Bytes', min_value=0)
            dstbytes = st.number_input('Destination Bytes', min_value=0)
            lastflag = st.number_input('Last Flag', min_value=0)
        with col2:
            loggedin = st.selectbox('Logged In', [0, 1])
            count = st.number_input('Count', min_value=0)
            srvcount = st.number_input('Srv Count', min_value=0)
            serrorrate = st.number_input('Serror Rate', min_value=0.0, max_value=1.0)
            srvserrorrate = st.number_input('Srv Serror Rate', min_value=0.0, max_value=1.0)
        with col3:
            samesrvrate = st.number_input('Same Srv Rate', min_value=0.0, max_value=1.0)
            diffsrvrate = st.number_input('Diff Srv Rate', min_value=0.0, max_value=1.0)
            dsthostsrvcount = st.number_input('Dst Host Srv Count', min_value=0)
            dsthostsamesrvrate = st.number_input('Dst Host Same Srv Rate', min_value=0.0, max_value=1.0)
            dsthostdiffsrvrate = st.number_input('Dst Host Diff Srv Rate', min_value=0.0, max_value=1.0)
        with col4:
            dsthostsamesrcportrate = st.number_input('Dst Host Same Src Port Rate', min_value=0.0, max_value=1.0)
            dsthostsrvdiffhostrate = st.number_input('Dst Host Srv Diff Host Rate', min_value=0.0, max_value=1.0)
            dsthostserrorrate = st.number_input('Dst Host Serror Rate', min_value=0.0, max_value=1.0)
            dsthostsrvserrorrate = st.number_input('Dst Host Srv Serror Rate', min_value=0.0, max_value=1.0)
            dsthostrerrorrate = st.number_input('Dst Host Rerror Rate', min_value=0.0, max_value=1.0)

        # A dictionary to map string inputs to numerical or categorical data used by the model
        protocoltype = {'icmp': 0, 'tcp': 1, 'udp': 2}
        service = {'IRC': 0, 'X11': 1, 'Z39_50': 2, 'aol': 3, 'auth': 4, 'bgp': 5, 'courier': 6,
                   'csnet_ns': 7, 'ctf': 8, 'daytime': 9, 'discard': 10, 'domain': 11, 'domain_u': 12,
                   'echo': 13, 'eco_i': 14, 'ecr_i': 15, 'efs': 16, 'exec': 17, 'finger': 18, 'ftp': 19,
                   'ftp_data': 20, 'gopher': 21, 'harvest': 22, 'hostnames': 23, 'http': 24,
                   'http_2784': 25, 'http_443': 26, 'http_8001': 27, 'imap4': 28, 'iso_tsap': 29,
                   'klogin': 30, 'kshell': 31, 'ldap': 32, 'link': 33, 'login': 34, 'mtp': 35, 'name': 36,
                   'netbios_dgm': 37, 'netbios_ns': 38, 'netbios_ssn': 39, 'netstat': 40, 'nnsp': 41,
                   'nntp': 42, 'ntp_u': 43, 'other': 44, 'pm_dump': 45, 'pop_2': 46, 'pop_3': 47,
                   'printer': 48, 'private': 49, 'red_i': 50, 'remote_job': 51, 'rje': 52, 'shell': 53,
                   'smtp': 54, 'sql_net': 55, 'ssh': 56, 'sunrpc': 57, 'supdup': 58, 'systat': 59,
                   'telnet': 60, 'tftp_u': 61, 'tim_i': 62, 'time': 63, 'urh_i': 64, 'urp_i': 65,
                   'uucp': 66, 'uucp_path': 67, 'vmnet': 68, 'whois': 69}
        flag = {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7,
                'S3': 8, 'SF': 9, 'SH': 10}

        if st.button('Scan'):
            # Convert input data
            data = [[
                protocoltype[protocoltype_i], service[service_i], flag[flag_i], srcbytes, dstbytes,
                loggedin, count, srvcount, serrorrate, srvserrorrate, samesrvrate, diffsrvrate, dsthostsrvcount,
                dsthostsamesrvrate, dsthostdiffsrvrate, dsthostsamesrcportrate, dsthostsrvdiffhostrate,
                dsthostserrorrate, dsthostsrvserrorrate, dsthostrerrorrate, lastflag
            ]]

            # Define column names (example names, use your actual feature names)
            columns = [
                'protocoltype', 'service', 'flag', 'srcbytes', 'dstbytes', 'loggedin', 'count', 'srvcount',
                'serrorrate', 'srvserrorrate', 'samesrvrate', 'diffsrvrate', 'dsthostsrvcount', 'dsthostsamesrvrate',
                'dsthostdiffsrvrate', 'dsthostsamesrcportrate', 'dsthostsrvdiffhostrate', 'dsthostserrorrate',
                'dsthostsrvserrorrate', 'dsthostrerrorrate', 'lastflag'
            ]

            # Convert to DataFrame
            data = pd.DataFrame(data, columns=columns)
            data = scaler.transform(data)
            data = pd.DataFrame(data, columns=columns)

            # Make a prediction
            prediction = model.predict(data)

            # Calculate Probability
            probas = model.predict_proba(data)

            if prediction == 'DoS':
                prob = np.round(probas[:, 0][0]*100)
            elif prediction == 'Probe':
                prob = np.round(probas[:, 1][0]*100)
            elif prediction == 'R2L':
                prob = np.round(probas[:, 2][0]*100)
            elif prediction == 'U2R':
                prob = np.round(probas[:, 3][0]*100)
            else:
                prob = np.round(probas[:, 4][0]*100)

            # Display the prediction
            prediction_text = (
                f'Alert: There is a {prob}% chance that you are currently experiencing a Denial of Service(DoS) attack.'
                'Immediate action is required to mitigate the impact.'
                if prediction == 0 else
                f'Alert: There is a {prob}% chance that suspicious PROBING activity is occurring.'
                'Potential reconnaissance in progress.'
                if prediction == 1 else
                f'Alert: There is a {prob}% probability that a REMOTE-TO-LOCAL attack is underway.'
                'Unauthorized remote access attempt identified.'
                if prediction == 2 else
                f'Alert: There is a {prob}% chance that a USER-TO-ROOT attack is happening.'
                'Suspicious privilege escalation detected.'
                if prediction == 3 else
                f'You are SAFE! No anomalies or security threats detected with {prob}% certainty.'
            )

            # Display the prediction with fancy formatting
            st.markdown(
                f"<h4>{prediction_text}</h4>",
                unsafe_allow_html=True
            )
