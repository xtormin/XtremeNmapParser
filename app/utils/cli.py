import sys
import argparse

# Script arguments options

parser = argparse.ArgumentParser(
    add_help=True,
    description='%(prog)s parse the output information from an nmap XML file')

parser.add_argument('-f', '--nmapxmlfile',
                    help='Nmap XML file',
                    nargs='?',
                    type=str)
parser.add_argument('-d', '--nmapxmldir',
                    help='Directory with nmap XML files',
                    nargs='?',
                    type=str)
parser.add_argument('-o', '--outputformat',
                    help='Output file format [csv, xlsx].',
                    nargs='?',
                    type=str,
                    default="csv,xlsx,json")
parser.add_argument('-O', '--outputname',
                    help='Output file name.',
                    nargs='?',
                    type=str)
parser.add_argument('-v', '--verbose',
                    help='Verbose',
                    action="store_true")
parser.add_argument('-M', '--mergefiles',
                    help='Merge XML files from directory',
                    action="store_true")

# Script arguments functions
def get():
    return parser.parse_args()
def help():
    return parser.print_help(sys.stderr)
