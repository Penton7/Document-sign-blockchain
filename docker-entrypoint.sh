#!/bin/bash

# Apply database migrations
echo "Apply database migrations"
python run.py db upgrade

# Start server
echo "Starting server"
python run.py runserver