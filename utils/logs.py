import logging

def setup_logging():
    # Create a log handler for the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # Create a log handler for the file
    file_handler = logging.FileHandler(filename='app.log', mode='w')
    file_handler.setLevel(logging.DEBUG)

    # Log format for the file
    file_formatter = logging.Formatter(f'%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                       datefmt='%d-%b-%y %H:%M:%S')

    # Log format for the console
    console_formatter = logging.Formatter('%(message)s')

    # Set the format for the handlers
    console_handler.setFormatter(console_formatter)
    file_handler.setFormatter(file_formatter)

    # Configure the logging
    logging.basicConfig(handlers=[file_handler, console_handler],
                        level=logging.DEBUG)