import pandas as pd

class ScanData:
    def __init__(self, hostname=None,
                       addr=None,
                       host_state=None,
                       portid=None,
                       protocol=None,
                       port_state=None,
                       service_name=None,
                       service_product=None,
                       service_version=None,
                       service_extrainfo=None):

        self.hostname = hostname
        self.addr = addr
        self.host_state = host_state
        self.portid = portid
        self.protocol = protocol
        self.port_state = port_state
        self.service_name = service_name
        self.service_product = service_product
        self.service_version = service_version
        self.service_extrainfo = service_extrainfo

    def to_list(self):
        return [self.hostname,
                self.addr,
                self.host_state,
                self.portid,
                self.protocol,
                self.port_state,
                self.service_name,
                self.service_product,
                self.service_version,
                self.service_extrainfo]

    def to_dataframe(self, headers, scandata_list):
        return pd.DataFrame(scandata_list, columns=headers)