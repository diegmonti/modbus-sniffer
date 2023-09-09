#!/bin/bash

source venv/bin/activate
./sniffer -p /dev/ttyUSB0 2>/dev/null | python pdc_exporter.py
