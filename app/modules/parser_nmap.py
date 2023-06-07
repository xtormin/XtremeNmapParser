import confuse
import pandas as pd
import xml.etree.ElementTree as ET
from app.utils.logs import CustomLogger

# Logging configuration
logger = CustomLogger('test')

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

HEADERS = config['xlsx']['headers'].get()

def parser(nmapxmlfile):
    try:
        tree = ET.parse(nmapxmlfile)
        root = tree.getroot()

        output = []

        for host in root.findall('host'):
            addr = host.find('address').get('addr')
            state = host.find('status').get('state')
            ports = host.find('ports')
            host_name = None

            if host.find('hostnames') is not None:
                for hostname in host.find('hostnames'):
                    hostname_type = hostname.get('type')
                    if hostname_type == 'user':
                        host_name = hostname.get('name')

            if state == 'up':
                for port in ports:
                    portid = port.get('portid')
                    protocol = None
                    if port.get('protocol') is not None:
                        protocol = port.get('protocol')

                    if port.find('state') is not None:
                        state_port = port.find('state').get('state')

                    if port.find('service') is not None:
                        service_name = port.find('service').get('name')
                        product = port.find('service').get('product')
                        version = port.find('service').get('version')
                        extrainfo = port.find('service').get('extrainfo')

                        output.append([host_name,
                                       addr,
                                       state,
                                       portid,
                                       protocol,
                                       state_port,
                                       service_name,
                                       product,
                                       version,
                                       extrainfo])

            df = pd.DataFrame(output, columns=HEADERS)

        return df

    except ET.ParseError as e:
        logger.error(f" |x| Error |  Error processing the {nmapxmlfile} XML file. It's possible that the scanner did not finish properly and the information is corrupted.")
        logger.error(e)

def parse_file(file_xml):
    logger.info(f" |+| Parsing | {file_xml}")
    df = parser(file_xml)
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