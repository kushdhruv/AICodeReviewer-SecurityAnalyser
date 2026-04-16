import logging
import sys

def get_logger(name: str) -> logging.Logger:
    """
    Creates and configures a standard industry-grade logger.
    """
    logger = logging.getLogger(name)
    
    # Avoid adding multiple handlers if logger already exists
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Console handler with standard formatting
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
    return logger
