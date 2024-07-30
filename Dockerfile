FROM python:3.10-slim

WORKDIR /streamlit-docker

RUN python3 -m pip install --upgrade pip
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

# Create the Streamlit config directory and copy the config file
RUN mkdir -p ~/.streamlit
COPY config.toml ~/.streamlit/config.toml

# Set the environment variable for the Streamlit config file
ENV STREAMLIT_CONFIG_FILE=~/.streamlit/config.toml

CMD ["python3", "-m", "streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]