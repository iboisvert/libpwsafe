FROM mcr.microsoft.com/devcontainers/base:ubuntu
RUN apt-get -y update \
    && apt-get -y install cmake gcc g++ gdb nettle-dev \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*
ENV DEBUGINFOD_URLS=https://debuginfod.ubuntu.com/