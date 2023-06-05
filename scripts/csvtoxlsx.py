import pandas as pd
import argparse

parser = argparse.ArgumentParser(
    add_help=True,
    description='%(prog)s CSV to XLSX.')

parser.add_argument('-c', '--csvfile',
                    help='XLSX output of CSV file',
                    nargs='?', type=str)

if __name__ == "__main__":
    args = parser.parse_args()

    filename = args.csvfile
    filename_xlsx = f"{filename}.xlsx"

    try:
        df = pd.read_csv(filename, sep=";")
        df.reset_index(drop=True)
        df.drop_duplicates(inplace=True)
        df.style.to_excel(filename_xlsx, index=False)
        print(f"|+| File created on {filename_xlsx}")
    except Exception as e:
        print("|+| File not created")
        print(e)
