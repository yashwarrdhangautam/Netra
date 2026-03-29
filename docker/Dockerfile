FROM python:3.12-slim AS builder
WORKDIR /app
RUN pip install poetry==1.8.4
COPY pyproject.toml poetry.lock* ./
RUN poetry config virtualenvs.create false && \
    poetry install --no-dev --no-interaction --no-ansi

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./
RUN useradd -m netra && chown -R netra:netra /app
USER netra
EXPOSE 8000
CMD ["uvicorn", "netra.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
