import json
import socketserver
from typing import Callable, Dict, Any, Tuple
from dataclasses import dataclass
from connection import Connection


class OracleServer(socketserver.TCPServer):
    """A server that evaluates player responses against registered test cases and stores results persistently."""

    pass
