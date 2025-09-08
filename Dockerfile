FROM python:3.12 AS base
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

FROM base AS build
COPY requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv .venv && \
    .venv/bin/pip install 'wheel==0.45.1' && \
    .venv/bin/pip install --no-deps -r /tmp/requirements.txt

FROM python:3.12-slim AS runtime
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
ENV PATH=/app/.venv/bin:$PATH
COPY --from=build /app/.venv /app/.venv
COPY . /app
ARG EZFAAS_BUILD_ID=''
ARG EZFAAS_COMMIT_ID=''
ENV EZFAAS_BUILD_ID=${EZFAAS_BUILD_ID} EZFAAS_COMMIT_ID=${EZFAAS_COMMIT_ID}

FROM runtime AS check
RUN python -m app.main --help

FROM runtime
CMD [ "/app/runserver.sh" ]
