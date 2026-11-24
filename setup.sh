#!/bin/bash

# create input and output files
echo "Creating input and output files..."
touch log.json
touch extracted_results.json
mkdir -p script_logs

# pull cowrie image
echo "Pulling Cowrie image..."
podman pull docker.io/cowrie/cowrie:latest

# create cowrie directory structure
echo "Creating cowrie directory structure..."
mkdir cowrie
mkdir cowrie/log
mkdir cowrie/downloads
mkdir cowrie/etc
touch cowrie/log/cowrie.json
chmod -R 777 cowrie 

read -p "Do you want to pull the extractor Docker images from Docker Hub? (y/n): " pull_images

if [[ "$pull_images" == "y" || "$pull_images" == "Y" ]]; then
    echo "Pulling extractor images from Docker Hub..."
    podman pull docker.io/marekconto/mozitools:latest
    podman pull docker.io/marekconto/mozibgone:latest
    podman pull docker.io/marekconto/miraicfg:latest
else
    echo "Skipping image pulling. If you want to build images manually:"
    echo "- Clone the original tool repositories into extractors/"
    echo "- Then run: podman build -t <tool> ."
    echo "Refer to README.md for instructions."
fi

echo "Environment setup complete!"


