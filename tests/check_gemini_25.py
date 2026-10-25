import os
import json
import time
import httpx
from fastapi import FastAPI, Request

# Let's inspect what happens when calling gemini-2.5-flash with timeout=12.0
