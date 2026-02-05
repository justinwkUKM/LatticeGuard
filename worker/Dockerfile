FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project definition
COPY pyproject.toml .
RUN uv pip install --system --no-cache -e .[test]

# Copy the entire project
COPY . .

# Run the worker
CMD ["python", "worker/worker.py"]
