import confuse
import pandas as pd
from lxml import etree
from app.utils.logs import CustomLogger

# Logging configuration
logger = CustomLogger('test')

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

HEADERS = config['xlsx']['headers'].get()

class NmapXMLtoDF:
    def __init__(self, xml_file):
        self.xml_file = xml_file

    def parse_xml(self):
        self.tree = etree.parse(self.xml_file)
        self.root = self.tree.getroot()

    def xml_to_df(self):
        try:
            self.parse_xml()
            data = []

            for host in self.root.iter('host'):
                addr = host.find('address').attrib['addr']
                state = host.find('status').attrib['state']
                ports = host.find('ports')

                hostnames = host.find('hostnames')
                host_name = None
                if hostnames is not None:
                    for hostname in hostnames:
                        if hostname.attrib.get('type') == 'user':
                            host_name = hostname.attrib['name']
                            break

                if state == 'up':
                    for port in ports:
                        portid = port.attrib.get('portid')
                        protocol = port.attrib.get('protocol')
                        state_port = port.find('state').attrib.get('state') if port.find('state') is not None else None

                        service = port.find('service')
                        if service is not None:
                            service_name = service.attrib.get('name')
                            product = service.attrib.get('product')
                            version = service.attrib.get('version')
                            extrainfo = service.attrib.get('extrainfo')

                            data.append([host_name,
                                           addr,
                                           state,
                                           portid,
                                           protocol,
                                           state_port,
                                           service_name,
                                           product,
                                           version,
                                           extrainfo])

                df = pd.DataFrame(data, columns=HEADERS)

            return df

        except etree.ParseError as e:
            logger.error(f" |x| Error |  Error processing the XML file. It's possible that the scanner did not finish properly and the information is corrupted.")
            logger.error(e)


def parse_file(xml_file):
    print(f" *** Parsing | {xml_file}")
    nmap_parser = NmapXMLtoDF(xml_file)
    df = nmap_parser.xml_to_df()
    return df

def merge_xml_files(xml_files):
    # Initialize a list to store the dataframes
    df_list = []

    # Loop over the XML files and append their data to df_all
    for xml_file in xml_files:
        df = parse_file(xml_file)

        # Append the dataframe to df_list
        df_list.append(df)

    # Concatenate all dataframes in df_list
    df_all = pd.concat(df_list, ignore_index=True)

    # Define the columns to check for non-null values
    cols_to_check = ['Service Name', 'Product', 'Version', 'Extrainfo']

    # Add a 'RelevantDuplicate' column that counts the number of non-null values in the specified columns for each row
    df_all['RelevantDuplicate'] = df_all[cols_to_check].notna().sum(axis=1)

    # Sort by 'IP', 'Port', 'State', 'RelevantDuplicate' (in descending order so larger counts come first), then drop duplicates
    df_all = df_all.sort_values(by=['IP', 'Port', 'State', 'RelevantDuplicate'], ascending=[True, True, False, False])
    df_all = df_all.drop_duplicates(subset=['IP', 'Port'], keep='first')

    # Convert 'Port' to int for proper sorting
    df_all['Port'] = df_all['Port'].astype(int)

    # Sort final dataframe by 'IP' and then 'Port'
    df_all = df_all.sort_values(by=['IP', 'Port'])

    return df_all