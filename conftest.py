"""pytest configuration — adds ingestion root to sys.path."""
import sys
import os

# Make sure the ingestion package root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
