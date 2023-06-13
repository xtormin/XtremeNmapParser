import confuse
import pandas as pd

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

HEADERS_ALL = config['xlsx']['headers_all'].get()

class ScanData:
    def __init__(self):
        self.data = {header: None for header in HEADERS_ALL}

    def to_list(self):
        return list(self.data.values())

    def to_dict(self):
        return self.data

    def to_dataframe(scan_data_list):
        df = None
        # Covert object list ScanData to a list of lists
        data_list = [sd.to_list() for sd in scan_data_list]
        # Use list of lists to create a DataFrame
        if data_list:
            df = pd.DataFrame(data_list, columns=list(scan_data_list[0].data.keys()))
            return df