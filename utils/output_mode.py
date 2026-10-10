"""Distinguish durable web results from user-requested CLI report files."""
import os


def web_scan():
    return os.environ.get('DAKSH_OUTPUT_MODE') == 'web'
