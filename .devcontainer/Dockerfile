FROM mcr.microsoft.com/devcontainers/base:ubuntu
RUN apt-get -y update \
    && apt-get -y install cmake clang libssl-dev libgtest-dev \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*