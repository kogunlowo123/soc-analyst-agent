#!/bin/bash
set -euo pipefail
echo "Setting up SOC Analyst Agent..."
pip install -e ".[dev]"
echo "Setup complete!"
