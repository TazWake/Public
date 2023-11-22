# Creating ELK for rapid evidence analysis

## Overview
This is designed to allow incident responders to create a quick Elasticsearch/Kibana/Filebeat instance to ingest log data. The end result will have excess fields and may require tweaking to work in specific environments. It uses the Elastic modules to provide pre-configured dashboards.

The configuration file assumes there are four types of event logs being ingested. This should be modified to fit your needs. It assumes the logs are

- Apache HTTPd access logs in the root of the log folder.
- Linux auditd logs in the root of the log folder.
- Linux syslog logs in the root of the log folder.
- Linux messages logs in the root of the log folder.
- Linux auth.log logs in the root of the log folder.
- Linux secure logs in the root of the log folder.

The output should look something like this initially:

![image](https://github.com/TazWake/Public/assets/26778008/67e6b8ed-fbea-4767-ac8a-faac62c4ca28)

**NOTE: It can take a few minutes for data to be ingested.**

## Components
The following files are required:

- docker-compose.yml
- kibana.yml
- filebeat.yml

### Preparation
Ensure that docker is installed on the system. For Ubuntu Linux, you could run:

`apt update && apt install docker-ce -y`

Alternatively, you can install docker desktop, docker or any other package that gives you the docker runtime and docker compose commands.

### Installation

#### Summary
To install this, copy the yml files to a folder on your system. Modify the files to make sure they point to the correct location for your evidence. Run docker compose to start the system.

#### Actions

1. Create a new location for the configuration files: `mkdir -p /opt/elk-files`
2. Copy all three yml files to that location.
3. Ensure your log data is in `/cases/logfiles` - if not, update the `docker-compose.yml` file to reflect the correct location.
4. Ensure that no other service is listening on localhost:8889. If it is, update the `docker-compose.yml` to reflect the port you want to use.
5. Run the compose script: `cd /opt/elk-files && sudo docker compose up -d`
6. You can log into your Kibana instance at http://localhost:8889
7. When you have finished the analysis, use `docker compose down` to close down the environment. **NOTE** Data is not persistent and will be lost on shutdown.
