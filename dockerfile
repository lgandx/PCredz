# syntax=docker/dockerfile:1
#FROM debian:buster-slim
FROM python:3.7.15-slim-buster

# Install apt packages
RUN apt update
RUN apt install python3 \
    python3-pip \
    libpcap-dev \
    file \
    nano \
    iproute2 \
    git \
    bash \
    bash-doc \
    bash-completion -y

# Create python symlink
RUN ln -s /usr/bin/python3 /usr/bin/python

# Install python things
RUN python -m pip install Cython
RUN python -m pip install python-libpcap

# Change our shell to /bin/bash
RUN sed -i '/root/s/ash/bash/g' /etc/passwd
CMD ["/bin/bash"]

# Make directory
RUN mkdir /opt/Pcredz

# Copy Pcredz files
COPY Pcredz /opt/Pcredz/
COPY logs /opt/Pcredz/logs

WORKDIR /opt/Pcredz/
