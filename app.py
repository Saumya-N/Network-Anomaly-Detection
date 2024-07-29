import streamlit as st
import importlib.util

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


# Login Page
def login_page():
    st.title('Login')
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        login(username, password)
    st.image('bkg.jpg')


# Main App
def main():
    if st.session_state.logged_in:
        page = st.selectbox("Select Page", ["Home", "Security Scan", "Reports"])
        if page == "Home":
            spec = importlib.util.spec_from_file_location("home.py", "home.py")
            home_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(home_module)
            home_module.home_page()
        elif page == "Security Scan":
            spec = importlib.util.spec_from_file_location("model.py", "model.py")
            ml_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ml_module)
            ml_module.detection_page()
        elif page == "Reports":
            spec = importlib.util.spec_from_file_location("report.py", "report.py")
            reports_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(reports_module)
            reports_module.reports_page()
    else:
        login_page()


if __name__ == "__main__":
    main()
