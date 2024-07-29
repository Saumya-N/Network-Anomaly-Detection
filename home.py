import streamlit as st


def logout():
    st.session_state.logged_in = False


# Home Page
def home_page():
    st.title('Home')
    st.write('Welcome to the Network Anomaly Detection App!')
    if st.button("Logout"):
        logout()
    st.image('bkg.jpg')
