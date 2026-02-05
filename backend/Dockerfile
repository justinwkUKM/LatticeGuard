FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

# Copy project definition
COPY pyproject.toml .

# Install dependencies using uv into the system python environment
RUN uv pip install --system --no-cache -e .[test]

# Copy the entire project
COPY . .

# Run the backend
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
