#!/usr/bin/env python3
"""
This script extracts some key exif data from a docx file.
It is not a replacement for exiftool or similar, but it can be used to make exifdata available for other tools.
"""

import docx
import sys
import getopt

def meta(doc):
    metadata = {}
    prop = doc.core_properties
    metadata["author"] = prop.author
    metadata["category"] = prop.category
    metadata["comments"] = prop.comments
    metadata["content_status"] = prop.content_status
    metadata["created"] = prop.created
    metadata["identifier"] = prop.identifier
    metadata["keywords"] = prop.keywords
    metadata["language"] = prop.language
    metadata["modified"] = prop.modified
    metadata["subject"] = prop.subject
    metadata["title"] = prop.title
    metadata["version"] = prop.version
    return metadata

def main(argv):
    input = ''
    try:
        opts, args = getopt.getopt(argv,"hi:")
    except getopt.GetoptError:
        print ("Use: exifcheck.py -i <inputfile>.docx")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ("exifcheck.py -i <inputfle>.docx")
            sys.exit()
        elif opt in ("-i"):
            input = arg
        doc = docx.Document(input)
        print("Opening : " + input)
        metadata_dict = meta(doc)
        print("Author: " + str(metadata_dict["author"]))
        print("Created: " + str(metadata_dict["created"]))
        print("Modified: " + str(metadata_dict["modified"]))
        print("Title: " + str(metadata_dict["title"]))
        print("Language: " + str(metadata_dict["language"]))

if __name__ == "__main__":
    main(sys.argv[1:])
