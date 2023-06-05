import sys
import confuse
import pandas as pd
import xml.etree.ElementTree as ET

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
    except Exception as e:
        print(f"|x| Error parsing | {nmapxmlfile}")
        sys.exit(0)
