import exiftool
import json
def write_custom_metadata(image_path, tag, value):
    # The absolute path to `exiftool.exe`
    exiftool_path =r"C:\Users\ASUS\Documents\exiftool-12.99_64\exiftool(-k).exe"

    # Pass this path explicitly to ExifTool
    with exiftool.ExifTool(executable=exiftool_path) as et:
        et.execute(b"-" + tag.encode() + b"=" + value.encode(), image_path.encode())
        print(f"Wrote: {tag} = {value}")

def read_custom_metadata(image_path, tag):
    # The absolute path to `exiftool.exe`
    exiftool_path =r"C:\Users\ASUS\Documents\exiftool-12.99_64\exiftool(-k).exe"
    with exiftool.ExifTool(executable=exiftool_path) as et:
        # Execute command to read metadata for the specified tag
        result = et.execute(f"-{tag}", image_path)

        # Parse the output to extract the value
        for line in result.splitlines():
            if result:
                # Split the line and extract the value after the colon
                value = line.split(":")[1].strip()
                return value

        return "Metadata not found"


def read_all_metadata(image_path):
    exiftool_path = r"C:\Users\ASUS\Documents\exiftool-12.99_64\exiftool(-k).exe"

    with exiftool.ExifTool(executable=exiftool_path) as et:
        # Execute command to read all metadata
        all_metadata = et.execute(b"-json", image_path.encode())

        # Decode the result and convert from JSON
        metadata_json = json.loads(all_metadata)

        # Print all metadata for debugging
        print(json.dumps(metadata_json, indent=4))