#!/bin/sh

pkill -9 -f main.py
pkill -9 -f doCollection.py
pkill -9 -f fte_relay
pkill -9 -f Xvfb
pkill -9 -f firefox
rm -rfv data
rm -rfv logs
