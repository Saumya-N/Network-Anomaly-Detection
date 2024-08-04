import streamlit as st
import pandas as pd
import numpy as np
import pickle

# Load model
with open('model/model.pkl', 'rb') as f:
    model, scaler = pickle.load(f)

# Dictionaries to map string inputs to numerical or categorical data
protocoltype = {'icmp': 0, 'tcp': 1, 'udp': 2}
service = {
    'IRC': 0, 'X11': 1, 'Z39_50': 2, 'aol': 3, 'auth': 4, 'bgp': 5, 'courier': 6,
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
    'uucp': 66, 'uucp_path': 67, 'vmnet': 68, 'whois': 69
}
flag = {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'SF': 9, 'SH': 10}


def detection_page():
    st.image('bkg.png', use_column_width=True)
    st.title('Network Anomaly Detection')
    col1, col2, col3, col4 = st.columns(4)
    uploaded_file = st.sidebar.file_uploader("Upload your network traffic data")

    if uploaded_file:
        data = pd.read_csv(uploaded_file)
        if 'protocoltype' in data.columns: data['protocoltype'] = data['protocoltype'].replace(protocoltype)
        if 'service' in data.columns: data['service'] = data['service'].replace(service)
        if 'flag' in data.columns: data['flag'] = data['flag'].replace(flag)

        if st.button('Scan'):
            data = scaler.transform(data)
            prediction = model.predict(data)
            probas = model.predict_proba(data)
            prob = np.round(probas[0][prediction[0]] * 100)
            alert_msgs = [
                f'Alert: There is a {prob}% chance that you are currently experiencing a Denial of Service (DoS) attack. Immediate action is required to mitigate the impact.',
                f'Alert: There is a {prob}% chance that suspicious PROBING activity is occurring. Potential reconnaissance in progress.',
                f'Alert: There is a {prob}% probability that a REMOTE-TO-LOCAL attack is underway. Unauthorized remote access attempt identified.',
                f'Alert: There is a {prob}% chance that a USER-TO-ROOT attack is happening. Suspicious privilege escalation detected.',
                f'You are SAFE! No anomalies or security threats detected with {prob}% certainty.'
            ]
            st.markdown(f"<h4>{alert_msgs[prediction[0]]}</h4>", unsafe_allow_html=True)

    else:
        protocoltype_i = col1.selectbox('Protocol Type', list(protocoltype.keys()))
        service_i = col1.selectbox('Service', list(service.keys()))
        flag_i = col1.selectbox('Flag', list(flag.keys()))
        srcbytes = col1.number_input('Source Bytes', min_value=0)
        dstbytes = col1.number_input('Destination Bytes', min_value=0)
        lastflag = col1.number_input('Last Flag', min_value=0)
        loggedin = col2.selectbox('Logged In', [0, 1])
        count = col2.number_input('Count', min_value=0)
        srvcount = col2.number_input('Srv Count', min_value=0)
        serrorrate = col2.number_input('Serror Rate', min_value=0.0, max_value=1.0)
        srvserrorrate = col2.number_input('Srv Serror Rate', min_value=0.0, max_value=1.0)
        samesrvrate = col3.number_input('Same Srv Rate', min_value=0.0, max_value=1.0)
        diffsrvrate = col3.number_input('Diff Srv Rate', min_value=0.0, max_value=1.0)
        dsthostcount = col3.number_input('Dst Host Count', min_value=0)
        dsthostsrvcount = col3.number_input('Dst Host Srv Count', min_value=0)
        dsthostsamesrvrate = col3.number_input('Dst Host Same Srv Rate', min_value=0.0, max_value=1.0)
        dsthostdiffsrvrate = col4.number_input('Dst Host Diff Srv Rate', min_value=0.0, max_value=1.0)
        dsthostsamesrcportrate = col4.number_input('Dst Host Same Src Port Rate', min_value=0.0, max_value=1.0)
        dsthostsrvdiffhostrate = col4.number_input('Dst Host Srv Diff Host Rate', min_value=0.0, max_value=1.0)
        dsthostserrorrate = col4.number_input('Dst Host Serror Rate', min_value=0.0, max_value=1.0)
        dsthostsrvserrorrate = col4.number_input('Dst Host Srv Serror Rate', min_value=0.0, max_value=1.0)

        if st.button('Scan'):
            input_data = [[
                protocoltype[protocoltype_i], service[service_i], flag[flag_i], srcbytes, dstbytes, loggedin, count,
                srvcount, serrorrate, srvserrorrate, samesrvrate, diffsrvrate, dsthostcount, dsthostsrvcount, dsthostsamesrvrate,
                dsthostdiffsrvrate, dsthostsamesrcportrate, dsthostsrvdiffhostrate, dsthostserrorrate, dsthostsrvserrorrate, lastflag
            ]]
            columns = [
                'protocoltype', 'service', 'flag', 'srcbytes', 'dstbytes', 'loggedin', 'count', 'srvcount', 'serrorrate',
                'srvserrorrate', 'samesrvrate', 'diffsrvrate', 'dsthostcount', 'dsthostsrvcount', 'dsthostsamesrvrate', 'dsthostdiffsrvrate',
                'dsthostsamesrcportrate', 'dsthostsrvdiffhostrate', 'dsthostserrorrate', 'dsthostsrvserrorrate','lastflag'
            ]
            data = pd.DataFrame(input_data, columns=columns)
            data = scaler.transform(data)
            prediction = model.predict(data)
            probas = model.predict_proba(data)
            prob = np.round(probas[0][prediction[0]] * 100)
            alert_msgs = [
                f'Alert: There is a {prob}% chance that you are currently experiencing a Denial of Service (DoS) attack. Immediate action is required to mitigate the impact.',
                f'Alert: There is a {prob}% chance that suspicious PROBING activity is occurring. Potential reconnaissance in progress.',
                f'Alert: There is a {prob}% probability that a REMOTE-TO-LOCAL attack is underway. Unauthorized remote access attempt identified.',
                f'Alert: There is a {prob}% chance that a USER-TO-ROOT attack is happening. Suspicious privilege escalation detected.',
                f'You are SAFE! No anomalies or security threats detected with {prob}% certainty'
                ]
            st.markdown(f"<h4>{alert_msgs[prediction[0]]}</h4>", unsafe_allow_html=True)
