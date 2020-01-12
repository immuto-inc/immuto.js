#!/bin/bash
echo "Deploying new version to NPM"
echo "WARNING: This script will run git commit and push to any added files"
echo "Current version information"
npm view immuto-backend
echo 

echo "Enter new version number for update"
read version
npm --set version $version

git add package.json
git commit -m "bumping version number for update"
git push

npm publish
