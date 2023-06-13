import os
import confuse

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

APPNAME = config['appname'].get()
NMAP_FILE_EXTENSION = config['nmap_file_extension'].get()

def get_dir_files(dir):
    return os.listdir(dir)

def get_dir_files_recursive(folder):
    xml_files = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.endswith(NMAP_FILE_EXTENSION):
                xml_files.append(os.path.join(root, file))
    return xml_files