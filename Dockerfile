FROM docker.io/python:3.13.11-slim-bookworm

ARG APP_HOME=/app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install --no-install-recommends -y \
    build-essential \
    # ssdeep / fuzzy hashing dependencies.
    libfuzzy-dev \
    # actual ssdeep binary incase you want a CLI option
    ssdeep

WORKDIR ${APP_HOME}

RUN pip install --upgrade \
    pip \
    "setuptools<70" \
    wheel

# Set constraint to ensure ssdeep build uses compatible setuptools.
ENV PIP_CONSTRAINT=/tmp/constraints.txt
RUN echo "setuptools<70" > /tmp/constraints.txt

RUN pip install ssdeep==3.4

COPY ./compare_ssdeep_ppdeep.py .

# Pick a ppdeep version...

# 1) Current 20251115 ppdeep version
RUN pip install ppdeep==20251115

# 2) Updated ppdeep PR
# COPY ./ppdeep.py .
# COPY ./setup.py .
# COPY ./README.md .
# RUN python setup.py install
