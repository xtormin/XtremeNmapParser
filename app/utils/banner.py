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
                                               
    By: @xtormin
    Github: https://github.com/xtormin/XtremeNmapParser
        
    HAPPY HUNTING! }8·)
   
    """

    print(colored(BANNER, 'red', attrs=['bold']))

def print_arguments_info(file_xml, folder, merger, output_format_list, output_name):

    BANNER = f"""  
 --------------------------------------------------------------  
 | Arguments information  
 --------------------------------------------------------------  
 | File (-f)          | {file_xml}  
 | Folder (-d)        | {folder}  
 | Merge files (-M)   | {merger}  
 | Output format (-o) | {output_format_list}  
 | Output name (-O)   | {output_name}  
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
