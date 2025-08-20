FROM python:3.13-slim

ENV POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache \
    POETRY_TIMEOUT=300 \
    POETRY_HTTP_TIMEOUT=300 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_TIMEOUT=300 \
    PIP_RETRIES=3

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libpq-dev \
    pkg-config \
    postgresql-client \
  && rm -rf /var/lib/apt/lists/*

# Install Poetry with better timeout handling
RUN pip install --no-cache-dir --timeout=300 poetry

# Configure Poetry for better stability
RUN poetry config installer.max-workers 1 && \
    poetry config experimental.new-installer false

WORKDIR /app

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh \
    && sed -i 's/\r$//' /usr/local/bin/entrypoint.sh

# Copy dependency files
COPY pyproject.toml poetry.lock* /app/

# Debug information (remove after fixing)
RUN echo "Python version:" && python --version && \
    echo "Poetry version:" && poetry --version && \
    echo "Poetry config:" && poetry config --list

# Clear any existing Poetry cache and install dependencies
RUN poetry cache clear --all pypi || true
RUN poetry install --only main --no-root --timeout=300 --verbose

COPY . /app

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]