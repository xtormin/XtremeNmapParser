from termcolor import colored
def main():
    BANNER = """
                                                
                    _____   ______        _____   
   _____      _____|\    \ |\     \   ___|\    \  
   \    \    /    / \\    \| \     \ |    |\    \ 
    \    \  /    /   \|    \  \     ||    | |    |
     \____\/____/     |     \  |    ||    |/____/|
     /    /\    \     |      \ |    ||    ||    ||
    /    /  \    \    |    |\ \|    ||    ||____|/
   /____/ /\ \____\   |____||\_____/||____|       
   |    |/  \|    |   |    |/ \|   |||    |       
   |____|    |____|   |____|   |___|/|____|       
     \(        )/       \(       )/    \(         
      '        '         '       '      '         
                                               
    Github: https://github.com/xtormin/XtremeNmapParser
    By: @xtormin
    
    HAPPY HACKING! }8·)
   
    """

    print(colored(BANNER, 'red', attrs=['bold']))

def print_arguments_info(single_xml, folder_multiple_xml, list_output_format, file_output_name, merger):

    BANNER = f"""  
 --------------------------------------------------------------  
 | Arguments information  
 --------------------------------------------------------------  
 | File (-f)          | {single_xml}  
 | Folder (-d)        | {folder_multiple_xml}  
 | Merge files (-M)   | {merger}  
 | Output format (-o) | {list_output_format}  
 | Output name (-O)   | {file_output_name}  
 --------------------------------------------------------------  
"""
    print(colored(BANNER, 'blue', attrs=['bold']))

def print_progress_info():

    BANNER = """
 --------------------------------------------------------------
 | Parsing files
 --------------------------------------------------------------
"""
    print(colored(BANNER, 'blue', attrs=['bold']))

def print_output_files_info():

    BANNER = """
 --------------------------------------------------------------
 | Output files
 --------------------------------------------------------------
"""
    print(colored(BANNER, 'blue', attrs=['bold']))
