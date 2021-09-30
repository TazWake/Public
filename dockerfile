# This is an example of a dockerfile

FROM uuntu:latest

# Create testing folder
RUN mkdir -p /opt/nmap

# Install nmap
RUN apt update && \
    apt install nmap -y

# Run scan
ENTRYPOINT [ "/bin/bash" ]
CMD ["nmap","-h"
