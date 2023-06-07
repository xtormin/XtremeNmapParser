import logging
import coloredlogs

class CustomLogger(logging.Logger):
    def __init__(self, name):
        super().__init__(name)

        # Define format for the messages
        format_str = '%(message)s'
        formatter = logging.Formatter(format_str)

        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)
        self.addHandler(ch)

        # Define log colors
        coloredlogs.DEFAULT_LOG_FORMAT = format_str
        coloredlogs.DEFAULT_LEVEL_STYLES = {
            'debug': {'color': 'cyan'},
            'info': {'color': 'green'},
            'warning': {'color': 'yellow', 'bold': True},
            'error': {'color': 'red'},
            'critical': {'color': 'red', 'bold': True}
        }

        coloredlogs.install(level='DEBUG', logger=self)