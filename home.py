import streamlit as st


# Home Page
def home_page():
    st.image('bkg.png', use_column_width=True)
    st.title('Home')
    st.write('Welcome to the Network Anomaly Detection App!')
