import random
import socket
import struct
from datetime import datetime, timedelta

# Configuration
output_file = "fake_access_log_updated.txt"
user_agent_file = "user_agents.txt"
referrer_file = "referrers.txt"
page_names_file = "page_names.txt"
start_time = datetime(2023, 12, 1, 18, 48)
end_time = datetime(2023, 12, 3, 19, 33)
num_entries = random.randint(3000000, 6000000)

# Calculate time interval
time_interval = (end_time - start_time) / num_entries

# Load data from files
with open(user_agent_file, "r") as ua_file:
    user_agents = [line.strip() for line in ua_file]

with open(referrer_file, "r") as ref_file:
    referrers = [line.strip() for line in ref_file]

with open(page_names_file, "r") as page_file:
    page_names = [line.strip() for line in page_file]

# Open the output log file
with open(output_file, "w") as log_file:
    current_time = start_time
    ip153_entry_count = 0  # Track the number of entries with IP 86.184.120.153
    ip49_entry_count = 0   # Track the number of entries with IP 157.245.137.49
    ip82_entry_count = 0   # Track the number of entries with IP 54.27.144.82
    ip88_entry_count = 0   # Track the number of entries with IP 54.27.144.88
    ip12_entry_count = 0   # Track the number of entries with IP 54.27.145.12
    ip156_entry_count = 0  # Track the number of entries with IP 54.27.144.156
    ip101_entry_count = 0  # Track the number of entries with IP 54.27.144.101
    ip177_entry_count = 0  # Track the number of entries with IP 54.27.144.177
    ip35_entry_count = 0   # Track the number of entries with IP 54.27.144.35

    for i in range(num_entries):
        # Check if it's time for the additional entries with IP 86.184.120.153
        if (
            ip153_entry_count < 2348
            and i % (50 * 60 * 5) < (3 * 60 * 5)
            and random.random() < 0.4
        ):
            # Generate entries for the specified duration
            for _ in range(3 * 60 * 5):
                timestamp = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
                for num in range(1678371625, 1678389626):
                    log_entry = f'86.184.120.153 - - [{timestamp}] "OPTIONS / HTTP/1.1" 302 - "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"\n'
                    log_file.write(log_entry.replace("NUMBERS", str(num)))
                    ip153_entry_count += 1
                    if ip153_entry_count >= 300:
                        break
                if ip153_entry_count >= 300:
                    break
                current_time += timedelta(seconds=1)
        elif i % (13 * 60 + 27) == 0 and random.random() < 0.5:
            log_entry = f'157.245.137.49 - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /b734k.php HTTP/1.1" 200 8880 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"\n'
            log_file.write(log_entry)
            ip49_entry_count += 1
        elif i % (13 * 60 + 28) == 0:
            log_entry = f'157.245.137.49 - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /b734k.php HTTP/1.1" 200 6757 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"\n'
            log_file.write(log_entry)
            ip49_entry_count += 1
        elif i % 100 == 0 and random.random() < 0.6:
            log_entry = f'54.27.144.82 - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /data.html HTTP/1.1" 200 6757 "/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"\n'
            log_file.write(log_entry)
            ip82_entry_count += 1
        elif i % 117 == 0 and random.random() < 0.3:
            log_entry = f'54.27.144.88 - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /data.html HTTP/1.1" 200 6757 "/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"\n'
            log_file.write(log_entry)
            ip88_entry_count += 1
        elif i % 122 == 0 and random.random() < 0.7:
            log_entry = f'54.27.145.12 - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /data.html HTTP/1.1" 200 6757 "/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"\n'
            log_file.write(log_entry)
            ip12_entry_count += 1
        elif i % 139 == 0 and random.random() < 0.45:
            log_entry = f'54.27.144.156 - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /data.html HTTP/1.1" 200 6757 "/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"\n'
            log_file.write(log_entry)
            ip156_entry_count += 1
        elif i % 168 == 0 and random.random() < 0.6:
            log_entry = f'54.27.144.101 - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /data.html HTTP/1.1" 200 6757 "/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"\n'
            log_file.write(log_entry)
            ip101_entry_count += 1
        elif i % 250 == 0 and random.random() < 0.2:
            log_entry = f'54.27.144.177 - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /data.html HTTP/1.1" 200 6757 "/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"\n'
            log_file.write(log_entry)
            ip177_entry_count += 1
        elif i % 489 == 0 and random.random() < 0.45:
            log_entry = f'54.27.144.35 - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /data.html HTTP/1.1" 200 6757 "/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"\n'
            log_file.write(log_entry)
            ip35_entry_count += 1
        else:
            # Generate source IP address (valid internet routable)
            source_ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

            # Generate HTTP request method (80% GET, 20% POST)
            if random.random() < 0.8:
                http_method = "GET"
            else:
                http_method = "POST"

            # Add HEAD request at random intervals with a blank referrer
            if random.random() < 0.005:  # 0.5% chance
                http_method = "HEAD"
                referrer = "-"
                page = "/"
            else:
                referrer = random.choice(referrers)
                page = random.choice(page_names)

            # Generate a random user agent
            user_agent = random.choice(user_agents)

            # Generate response codes (60% 200, 40% random)
            if random.random() < 0.6:
                response_code = "200"
            else:
                response_code = random.choice(["404", "302", "301", "500", "401"])

            # Generate file size (4782 if 'index' in page name, otherwise random between 1287 and 12652)
            if "index" in page:
                file_size = "4782"
            else:
                file_size = str(random.randint(1287, 12652))

            # Write the log entry with modified fields
            log_entry = f'{source_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{http_method} {page} HTTP/1.1" {response_code} {file_size} "{referrer}" "{user_agent}"\n'

            # Introduce a 10% chance of writing the same log entry twice
            if random.random() < 0.1:
                log_file.write(log_entry)  # Write the log entry once
                log_file.write(log_entry)  # Write the log entry again
            else:
                log_file.write(log_entry)  # Write the log entry once

            # Write the log entry to the file
            #log_file.write(log_entry)

        # Increment the timestamp
        current_time += time_interval

        # Check if the specified number of entries has been reached
        if i == num_entries - 1:
            break

print(f"Generated {num_entries} log entries in '{output_file}'")
