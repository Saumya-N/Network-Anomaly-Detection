import streamlit as st
import pickle
import numpy as np

# Load model
with open('model/model.pkl', 'rb') as f:
    model, scaler = pickle.load(f)

# Set page width
st.set_page_config(layout="wide")

# Initialize session state for login
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

# Dummy user credentials
USERNAME = "user"
PASSWORD = "pass"


def login(username, password):
    if username == USERNAME and password == PASSWORD:
        st.session_state.logged_in = True
    else:
        st.error("Invalid username or password")


def logout():
    st.session_state.logged_in = False

# Login Page


def login_page():
    st.title('Login')
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        login(username, password)
    st.image('bkg.jpg')

# Home Page


def home_page():
    st.title('Home')
    st.write('Welcome to the Network Anomaly Detection App!')
    if st.button("Logout"):
        logout()
    st.image('bkg.jpg')

# Prediction Page


def prediction_page():

    # Title of the app
    st.title('Network Anomaly Detection')

    # Create a 5-column layout
    col1, col2, col3, col4 = st.columns(4)

    # Input form
    with col1:
        duration = st.number_input('Duration', min_value=0)
        protocol_type = st.selectbox('Protocol Type', ['tcp', 'udp', 'icmp'])
        service = st.selectbox('Service', [
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
        flag = st.selectbox('Flag', ['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'RSTOS0', 'S3', 'S2', 'OTH'])
        src_bytes = st.number_input('Source Bytes', min_value=0)
        dst_bytes = st.number_input('Destination Bytes', min_value=0)
        land = st.selectbox('Land', [0, 1])
        # Conditional selection for wrong_fragment
        if protocol_type == 'udp':
            wrong_fragment = st.selectbox('Wrong Fragment', [0, 1, 3])
        elif protocol_type == 'icmp':
            wrong_fragment = st.selectbox('Wrong Fragment', [0, 1])
        else:  # udp
            wrong_fragment = st.selectbox('Wrong Fragment', [0])
        urgent = st.selectbox('Urgent', [0, 1, 2, 3])
        hot = st.number_input('Hot', min_value=0)
        numfailedlogins = st.number_input('Number of Failed Logins', min_value=0)
    with col2:
        loggedin = st.selectbox('Logged In', [0, 1])
        numcompromised = st.number_input('Number of Compromised Conditions', min_value=0)
        root_shell = st.selectbox('Root Shell', [0, 1])
        su_attempted = st.selectbox('Su Attempted', [0, 1])
        num_root = st.number_input('Num Root', min_value=0)
        num_file_creations = st.number_input('Num File Creations', min_value=0)
        num_shells = st.number_input('Num Shells', min_value=0)
        num_access_files = st.number_input('Num Access Files', min_value=0)
        num_outbound_cmds = st.number_input('Num Outbound Cmds', min_value=0)
        is_host_login = st.selectbox('Is Host Login', [0, 1])
        is_guest_login = st.selectbox('Is Guest Login', [0, 1])
    with col3:
        count = st.number_input('Count', min_value=0)
        srv_count = st.number_input('Srv Count', min_value=0)
        serror_rate = st.number_input('Serror Rate', min_value=0.0, max_value=1.0)
        srv_serror_rate = st.number_input('Srv Serror Rate', min_value=0.0, max_value=1.0)
        rerror_rate = st.number_input('Rerror Rate', min_value=0.0, max_value=1.0)
        srv_rerror_rate = st.number_input('Srv Rerror Rate', min_value=0.0, max_value=1.0)
        same_srv_rate = st.number_input('Same Srv Rate', min_value=0.0, max_value=1.0)
        diff_srv_rate = st.number_input('Diff Srv Rate', min_value=0.0, max_value=1.0)
        srv_diff_host_rate = st.number_input('Srv Diff Host Rate', min_value=0.0, max_value=1.0)
        dst_host_count = st.number_input('Dst Host Count', min_value=0)
        dst_host_srv_count = st.number_input('Dst Host Srv Count', min_value=0)
    with col4:
        dst_host_same_srv_rate = st.number_input('Dst Host Same Srv Rate', min_value=0.0, max_value=1.0)
        dst_host_diff_srv_rate = st.number_input('Dst Host Diff Srv Rate', min_value=0.0, max_value=1.0)
        dst_host_same_src_port_rate = st.number_input('Dst Host Same Src Port Rate', min_value=0.0, max_value=1.0)
        dst_host_srv_diff_host_rate = st.number_input('Dst Host Srv Diff Host Rate', min_value=0.0, max_value=1.0)
        dst_host_serror_rate = st.number_input('Dst Host Serror Rate', min_value=0.0, max_value=1.0)
        dst_host_srv_serror_rate = st.number_input('Dst Host Srv Serror Rate', min_value=0.0, max_value=1.0)
        dst_host_rerror_rate = st.number_input('Dst Host Rerror Rate', min_value=0.0, max_value=1.0)
        dst_host_srv_rerror_rate = st.number_input('Dst Host Srv Rerror Rate', min_value=0.0, max_value=1.0)
        last_flag = st.number_input('Last Flag', min_value=0)

    # A dictionary to map string inputs to numerical or categorical data used by the model
    protocol_type_dict = {'icmp': 0, 'tcp': 1, 'udp': 2}
    service_dict = {'IRC': 0, 'X11': 1, 'Z39_50': 2, 'aol': 3, 'auth': 4, 'bgp': 5, 'courier': 6,
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
    flag_dict = {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7,
                 'S3': 8, 'SF': 9, 'SH': 10}

    if st.button('Verify'):
        # Convert input data
        data = [
            duration, protocol_type_dict[protocol_type], service_dict[service], flag_dict[flag], src_bytes, dst_bytes,
            land, wrong_fragment, urgent, hot, numfailedlogins, loggedin, numcompromised, root_shell, su_attempted,
            num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds, is_host_login,
            is_guest_login, count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate,
            diff_srv_rate, srv_diff_host_rate, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
            dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate,
            dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate, last_flag
        ]

        # Scaling the data
        data = np.array(data).reshape(1, -1)
        data = scaler.transform(data)

        # Make a prediction
        prediction = model.predict(data)

        # Display the prediction
        prediction_text = (
            'Under DoS Attack' if prediction == 0 else
            'Under Probe Attack' if prediction == 1 else
            'Under R2L Attack' if prediction == 2 else
            'Under U2R Attack' if prediction == 3 else
            'You are SAFE!'
        )

        # Display the prediction with fancy formatting
        st.markdown(
            f"<h2><strong>{prediction_text}</strong></h2>",
            unsafe_allow_html=True
        )
    st.image('bkg.jpg')
# Reports Page


def reports_page():
    st.title('Reports')
    st.write('This is the Reports page. You can add content for reports here.')

# Main App


def main():
    if st.session_state.logged_in:
        page = st.sidebar.selectbox("Select Page", ["Home", "Prediction", "Reports"])
        if page == "Home":
            home_page()
        elif page == "Prediction":
            prediction_page()
        elif page == "Reports":
            reports_page()
    else:
        login_page()


if __name__ == "__main__":
    main()
