import streamlit as st


# Home Page
def home_page():
    st.image('bkg.png', use_column_width=True)
    st.title('Home')
    st.write('Welcome to the Network Anomaly Detection App!')

    # Embed video
    # Embed Loom video
    st.markdown("""
    <div style="position: relative; padding-bottom: 64.98194945848375%; height: 0;">
        <iframe src="https://www.loom.com/embed/188dd624e4a6498b9c4e488a2519a31c?sid=c200d6e9-e37e-486c-bb42-391e9e72f39f" 
                frameborder="0" 
                webkitallowfullscreen 
                mozallowfullscreen 
                allowfullscreen 
                style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;">
        </iframe>
    </div>
    """, unsafe_allow_html=True)