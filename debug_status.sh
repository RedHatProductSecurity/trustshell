#!/bin/bash

while true; do
  uv run trust-prime -c -d
  sleep 60 # Sleep for 60 seconds (1 minute)
done
