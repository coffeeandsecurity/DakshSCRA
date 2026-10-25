"""Bounded report reading and atomic streaming JSON publication."""
import json
import os
from pathlib import Path
import tempfile
from functools import lru_cache
from contextlib import contextmanager


@lru_cache(maxsize=8192)
def _shared_string(value):
    return value


def _share_record_strings(record):
    """Share immutable repeated path/text values across flow records."""
    def share(value):
        return _shared_string(value) if isinstance(value, str) and len(value) <= 4096 else value
    result = {}
    for key, value in record.items():
        if isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, str):
                    value[index] = share(item)
        result[share(key)] = share(value)
    return result


@contextmanager
def atomic_json_stream(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.analysis-', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            yield stream
        os.replace(temporary, path)
    except OSError as exc:
        raise OSError(exc.errno, exc.strerror or str(exc), str(path)) from exc
    except MemoryError as exc:
        raise MemoryError('Could not serialize analyzer output: ' + str(path)) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_json_atomic(path, payload, indent=2):
    with atomic_json_stream(path) as stream:
        json.dump(payload, stream, indent=indent)


def iter_json_array(path, chunk_size=65536, max_record_chars=64 * 1024 * 1024):
    """Read generated flow records without retaining a second full JSON document.

    Reject malformed/truncated output and oversized individual records rather
    than silently reporting an empty or partially read array as complete.
    """
    decoder = json.JSONDecoder(object_hook=_share_record_strings)
    if chunk_size <= 0 or max_record_chars <= 0:
        raise ValueError('JSON read limits must be positive')
    with Path(path).open(encoding='utf-8') as stream:
        buffer, eof = '', False

        def fill():
            nonlocal buffer, eof
            chunk = stream.read(chunk_size)
            eof = not chunk
            buffer += chunk

        def whitespace():
            nonlocal buffer
            buffer = buffer.lstrip(' \t\r\n')
            while not buffer and not eof:
                fill()
                buffer = buffer.lstrip(' \t\r\n')

        whitespace()
        if not buffer.startswith('['):
            raise ValueError('Analyzer report must contain a JSON array')
        buffer = buffer[1:]
        first = True
        while True:
            whitespace()
            if first and buffer.startswith(']'):
                buffer = buffer[1:]
                break
            while True:
                try:
                    item, end = decoder.raw_decode(buffer)
                    if end > max_record_chars:
                        raise ValueError('Analyzer JSON record exceeds the safe read limit; analysis is incomplete')
                    tail = buffer[end:].lstrip(' \t\r\n')
                    if tail[:1] in (',', ']'):
                        break
                    if eof:
                        raise ValueError('Malformed or truncated analyzer JSON array')
                except json.JSONDecodeError as exc:
                    if eof:
                        raise ValueError('Malformed or truncated analyzer JSON array') from exc
                if len(buffer) > max_record_chars:
                    raise ValueError('Analyzer JSON record exceeds the safe read limit; analysis is incomplete')
                fill()
            separator = tail[0]
            buffer = tail[1:]
            yield item
            first = False
            if separator == ']':
                break
        whitespace()
        if buffer:
            raise ValueError('Unexpected content after analyzer JSON array')
