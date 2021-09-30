# This is an example of a dockerfile

FROM alpine:latest

# Create testing folder
RUN mkdir -p /opt/nmap

# Install nmap
RUN apk update && apk add nmap

# Run nmap
CMD ["nmap","-h"]
