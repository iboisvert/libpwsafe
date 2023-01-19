FROM ubuntu:22.04
RUN apt-get -y update \
    && apt-get -y install cmake gcc g++ nettle-dev rpm \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*