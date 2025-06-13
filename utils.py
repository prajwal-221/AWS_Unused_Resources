import logging
from typing import Any, Generator

def get_logger() -> logging.Logger:
    logger = logging.getLogger('access-analyzer')
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler = logging.FileHandler('access_analyzer_script.log')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    return logger

def paginate(client: Any, operation_name: str, **kwargs) -> Generator:
    """Helper to paginate through any boto3 list_* paginator."""
    paginator = client.get_paginator(operation_name)
    for page in paginator.paginate(**kwargs):
        yield page
