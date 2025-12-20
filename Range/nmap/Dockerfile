# Use Alpine Linux as the base image
FROM alpine:latest

# Create a directory called /nmap
RUN mkdir /nmap

# Install nmap
RUN apk add --no-cache nmap

# Create the run_nmap.sh script
COPY run_nmap.sh /nmap/run_nmap.sh
RUN chmod +x /nmap/run_nmap.sh

# Make the script executable
RUN chmod +x /nmap/run_nmap.sh

# Set the default command to run the script
CMD ["/nmap/run_nmap.sh"]
