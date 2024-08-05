import streamlit as st


# Home Page
def home_page():
    st.image('bkg.png', use_column_width=True)
    st.title('Home')
    st.write('Welcome to the Network Anomaly Detection App!')

    # Embed video
    st.video('https://www.loom.com/share/188dd624e4a6498b9c4e488a2519a31c?sid=97ae0d87-fd27-4df6-93d1-a305e55b47c6')