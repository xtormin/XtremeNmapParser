import sys
import argparse

# Script arguments options

parser = argparse.ArgumentParser(
    add_help=True,
    description='%(prog)s parse the output information from an nmap XML file')

parser.add_argument('-f', '--file',
                    help='Nmap XML file. Ej: xnp.py -f nmapfile.xml',
                    nargs='?',
                    type=str)
parser.add_argument('-d', '--directory',
                    help='Directory with nmap XML files. Ej: xnp.py -d nmap/',
                    nargs='?',
                    type=str)
parser.add_argument('-oF', '--outputformat',
                    choices=['csv', 'xlsx', 'json'],
                    help='Output file format (csv, xlsx, json). Ej: xnp.py -f nmapfile.xml -oF csv xlsx',
                    nargs='+',
                    type=str,
                    default=['csv', 'xlsx', 'json'])
parser.add_argument('-oN', '--outputname',
                    help='Output file name.',
                    nargs='?',
                    type=str)
parser.add_argument('-v', '--verbose',
                    help='Verbose',
                    action="store_true")
parser.add_argument('-M', '--merger',
                    help='Merge XML files from directory',
                    action="store_true")
parser.add_argument('-R', '--recursive',
                    help='Parse XML files from a directory recursively',
                    action="store_true")
parser.add_argument('-C', '--columns',
                    type=str,
                    choices=['default', 'all'],
                    help='Columns for the output dataframe')
parser.add_argument('--open',
                    help='Export only the ports with "open" value in "State Port"',
                    action="store_true")

# Script arguments functions
def get():
    return parser.parse_args()
def help():
    return parser.print_help(sys.stderr)
