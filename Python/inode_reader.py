import sys
import pytsk3

def extract_block(image, inode):
    # Open the disk image
    try:
        img = pytsk3.Img_Info(image)
    except IOError as e:
        print(f"Error opening image: {e}")
        sys.exit(1)

    # Open the filesystem on the image
    try:
        fs = pytsk3.FS_Info(img)
    except IOError as e:
        print(f"Error opening filesystem: {e}")
        sys.exit(1)

    # Get the inode structure
    try:
        inode_obj = fs.open_meta(inode)
    except IOError as e:
        print(f"Error opening inode: {e}")
        sys.exit(1)

    # Extract the data block
    block = inode_obj.read_random(0, inode_obj.info.meta.size)

    # Return the data block
    return block

if __name__ == "__main__":
    # Check for correct usage
    if len(sys.argv) != 3:
        print("Usage: python script.py disk_image inode")
        sys.exit(1)

    # Extract the block
    block = extract_block(sys.argv[1], int(sys.argv[2]))
    print(block)
