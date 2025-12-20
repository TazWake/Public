# Use Ubuntu 23.10 as the base image
FROM ubuntu:23.10

# Set environment variables for non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install necessary packages
RUN apt-get update && \
    apt-get install -y \
    nano \
    vim \
    unzip \
    curl \
    git-core \
    build-essential \
    locales \
    tzdata \
    openssh-server \
    tcpdump

# Create a user account called John
RUN useradd -ms /bin/bash john

# Set the language and keyboard layouts to en_US.UTF-8
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Set the timezone to MST
RUN ln -fs /usr/share/zoneinfo/America/Denver /etc/localtime && \
    dpkg-reconfigure --frontend noninteractive tzdata

# Configure SSH server
RUN mkdir -p /var/run/sshd && \
    echo 'john:password' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Set up John's working area
RUN mkdir -p /home/john/data

COPY binary /home/john/binary
RUN /home/john/binary &&

# Expose SSH port
EXPOSE 22
EXPOSE 8888

# Start tcpdump 
RUN tcpdump -i any -w /home/john/data/capture_$(date -u +%Y%m%dT%H:%M:%S).pcap -C 20 'port 8888'

# Start SSH service
CMD ["/usr/sbin/sshd", "-D"]