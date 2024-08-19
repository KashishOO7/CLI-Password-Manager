import os
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from git import Repo
import secrets
import getpass
import datetime, time
import hashlib
import requests
import winsound
from playsound import playsound

from rich import print
from rich.prompt import Confirm, Prompt, IntPrompt
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich.layout import Layout
from rich.style import Style
from rich.text import Text
from rich.align import Align
from rich.markdown import Markdown
from rich import errors
