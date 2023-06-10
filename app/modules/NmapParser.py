import confuse
import pandas as pd
from lxml import etree
from app.utils.logs import CustomLogger
from app.modules.NmapXMLReport import NmapXMLReport
from app.models.ScanData import ScanData

# Logging configuration
logger = CustomLogger('test')

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

HEADERS = config['xlsx']['headers'].get()

class NmapParser:
    def __init__(self, xml_file=None):
        self.xml_file = xml_file

    def get_simple_df(self):
        try:
            nmap_report = NmapXMLReport(self.xml_file)
            all_rows_dataframe = []
            for host in nmap_report.hosts:
                dataframe = ScanData()
                for hostname in host.hostnames:
                    for host_name in hostname.hostnames:
                        dataframe.hostname = host_name.name
                for address in host.addresses:
                    dataframe.addr = address.addr
                for status in host.status:
                    dataframe.host_state = status.state
                for port in host.ports:
                    dataframe.portid = port.portid
                    dataframe.protocol = port.protocol
                    for state in port.state:
                        dataframe.port_state = state.state
                    for service in port.service:
                        dataframe.service_name = service.name
                        dataframe.service_product = service.product
                        dataframe.service_version = service.version
                        dataframe.service_extrainfo = service.extrainfo

                        all_rows_dataframe.append(dataframe.to_list())

            df = dataframe.to_dataframe(HEADERS, all_rows_dataframe)
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

    def merge_df(xml_file_list):

        df = NmapParser.parse_file_multiple(xml_file_list)

        # Define the columns to check for non-null values
        cols_to_check = ['Product', 'Version', 'Extrainfo']

        # Add a 'RelevantDuplicate' column that counts the number of non-null values in the specified columns for each row
        df['RelevantDuplicate'] = df[cols_to_check].notna().sum(axis=1)

        # Sort by 'IP', 'Port', 'State', 'RelevantDuplicate' (in descending order so larger counts come first), then drop duplicates
        df = df.sort_values(by=['IP', 'Port', 'State', 'RelevantDuplicate'], ascending=[True, True, False, False])
        df = df.drop_duplicates(subset=['IP', 'Port'], keep='first')

        # Convert 'Port' to int for proper sorting
        df['Port'] = df['Port'].astype(int)

        # Sort final dataframe by 'IP' and then 'Port'
        df = df.sort_values(by=['IP', 'Port'])

        return df