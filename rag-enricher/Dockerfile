FROM python:3.12-slim
WORKDIR /app
# chroma-hnswlib is a C++ extension — needs build tools to compile
RUN apt-get update && apt-get install -y --no-install-recommends build-essential g++ && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
# Install CPU-only torch first to keep the image lean
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r requirements.txt
# Pre-download embedding model at build time (~90MB) to avoid runtime delay
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003"]
