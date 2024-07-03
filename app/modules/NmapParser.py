import confuse
import ipaddress
import pandas as pd
from lxml import etree
from app.utils.logs import CustomLogger
from app.modules.NmapXMLReport import NmapXMLReport
from app.models.ScanData import ScanData

# Logging configuration
logger = CustomLogger('test')

class NmapParser:
    def __init__(self, xml_file=None):
        self.xml_file = xml_file

    def get_simple_df(self):
        try:
            nmap_report = NmapXMLReport(self.xml_file)
            all_rows_dataframe = []
            for host in nmap_report.hosts:
                for port in host.ports:
                    dataframe = ScanData()
                    for hostname in host.hostnames:
                        for host_name in hostname.hostnames:
                            dataframe.data["Hostname"] = host_name.name
                    for address in host.addresses:
                        if address.addrtype == 'ipv4':
                            dataframe.data["IP"] = address.addr
                    for status in host.status:
                        dataframe.data["State"] = status.state
                    dataframe.data["Port"] = port.portid
                    dataframe.data["Protocol"] = port.protocol
                    script_data = []
                    for script in port.script:
                        script_data.append(script.__str__())
                    dataframe.data["Scripts"] = script_data
                    for state in port.state:
                        dataframe.data["State Port"] = state.state
                    for service in port.service:
                        dataframe.data["Service Name"] = service.name
                        dataframe.data["Product"] = service.product
                        dataframe.data["Version"] = service.version
                        dataframe.data["Extrainfo"] = service.extrainfo
                    all_rows_dataframe.append(dataframe)

            df = ScanData.to_dataframe(all_rows_dataframe)
            logger.info(f" |+| {self.xml_file} parsed successfully  ")
            return df

        except etree.ParseError as EPE:
            logger.error(
                f" |x| Error | Error processing the XML file. It's possible that the scanner did not finish properly and the information is corrupted.")
            logger.error(EPE)

        except UnboundLocalError as ULE:
            logger.warning(
                f" |?| Warning | The file may not have any information or may not exist.")
            logger.warning("UnboundLocalError: 'dataframe' variable was referenced before assignment. Ensure 'dataframe' is defined before attempting to call 'to_dataframe' on it.")
            logger.warning(ULE)


    def parse_file(self):
        print(f" *** Parsing | {self.xml_file}")
        nmap_parser = NmapParser(self.xml_file)
        df = nmap_parser.get_simple_df()
        return df

    def parse_file_multiple(xml_file_list):
        # Initialize a list to store the dataframes
        df_list = []

        # Loop over the XML files and append their data to df_all
        for xml_file in xml_file_list:
            df = NmapParser(xml_file).parse_file()

            # Append the dataframe to df_list
            df_list.append(df)

        # Concatenate all dataframes in df_list
        df = pd.concat(df_list, ignore_index=True)

        return df

    def is_not_ip(val):
        try:
            ipaddress.ip_address(val)
            return None
        except ValueError:
            return val

    def merge_df(xml_file_list):

        df = NmapParser.parse_file_multiple(xml_file_list)

        # Define the columns to check for non-null values
        cols_to_check = ['Product', 'Version', 'Extrainfo']

        # Add a 'RelevantDuplicate' column that counts the number of non-null values in the specified columns for each row
        df['RelevantDuplicate'] = df[cols_to_check].notna().sum(axis=1)

        # Sort by 'IP', 'Port', 'State', 'RelevantDuplicate' (in descending order so larger counts come first), then drop duplicates
        df = df.sort_values(by=['IP', 'Port', 'State', 'RelevantDuplicate'], ascending=[True, True, False, False])
        df = df.drop_duplicates(subset=['IP', 'Port'], keep='first')

        df['Hostname'] = df.groupby('IP')['Hostname'].transform(
            lambda x: x.fillna(method='ffill').fillna(method='bfill'))
        df['Hostname'] = df['Hostname'].apply(NmapParser.is_not_ip)

        return df
