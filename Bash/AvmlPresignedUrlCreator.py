import argparse
import datetime
import socket
import uuid
import boto3
from botocore.config import Config

# --- CONFIGURATION ---
BUCKET_NAME = "{ENTER BUCKET NAME HERE}"
EXPIRATION = 7200 # <--- this url will last for a while, make sure you really want it for this long.
REGION = "us-east-1"


def main():
    """
    Generate a presigned URL for uploading AVML memory dump to S3.
    
    This script creates a presigned URL that allows uploading a memory.lime file
    to the configured S3 bucket. The object key is constructed using the hostname
    and current timestamp.
    """
    parser = argparse.ArgumentParser(
        description="Generate a presigned URL for uploading AVML memory dump to S3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
    Use the system hostname automatically with default profile and region
  
  %(prog)s --hostname workstation-01
    Specify a custom hostname for the object key
  
  %(prog)s --profile myprofile --region us-west-2
    Use a custom AWS profile and region
  
  %(prog)s --hostname workstation-01 --profile myprofile --region us-west-2
    Specify all custom options
        """
    )
    parser.add_argument(
        "--hostname",
        "-H",
        type=str,
        default=None,
        help="Hostname to use in the object key (default: system hostname)"
    )
    parser.add_argument(
        "--profile",
        "-p",
        type=str,
        default="rangeadmin",
        help="AWS profile name to use (default: rangeadmin)" # <--- This assumes you have multiple profiles in your AWS config.
    )
    parser.add_argument(
        "--region",
        "-r",
        type=str,
        default=REGION,
        help=f"AWS region to use (default: {REGION})"
    )
    
    args = parser.parse_args()
    
    # Use provided hostname or fall back to system hostname
    hostname = args.hostname if args.hostname else socket.gethostname()
    
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    # OBJECT_KEY = f"{hostname}_{timestamp}_{uuid.uuid4().hex}_UAC.tar.gz" # <--- this line is commented out. If you want to append a random string to keep file names unique, uncomment this line.
    OBJECT_KEY = f"{hostname}_{timestamp}_memory.lime"

    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    sts = session.client("sts")
    # print("Signing as:", sts.get_caller_identity()["Arn"])

    s3 = session.client("s3", config=Config(signature_version="s3v4"))

    url = s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={
            "Bucket": BUCKET_NAME,
            "Key": OBJECT_KEY,
        },
        ExpiresIn=EXPIRATION,
        HttpMethod="PUT",
    )

    # print("Key:", OBJECT_KEY)
    print(url)


if __name__ == "__main__":
    main()