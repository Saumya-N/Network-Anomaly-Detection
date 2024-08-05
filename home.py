import streamlit as st


# Home Page
def home_page():
    st.image('bkg.png', use_column_width=True)
    st.title('Home')
    st.write('Welcome to the Network Anomaly Detection App!')

    # Embed video
    st.video('https://www.loom.com/share/188dd624e4a6498b9c4e488a2519a31c?sid=b8c b17b3-e84b-49de-976e-1d598fa4968b')