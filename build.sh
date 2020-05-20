#!/bin/bash

go get -v -t -d ./...

GOOS=darwin GOARCH=amd64 go build -o darwin-amd64/smtprelay .
GOOS=windows GOARCH=amd64 go build -o windows-amd64/smtprelay .
GOOS=linux GOARCH=amd64 go build -o linux-amd64/smtprelay .
GOOS=linux GOARCH=arm GOARM=5 go build -o linux-arm/smtprelay .
