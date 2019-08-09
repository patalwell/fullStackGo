# fullStackGo

This repository contains a web application that uses Okta 
for single sign on authorization, MDN bootstrap for UI/UX, 
GoLang for server side processing, and various JS libraries for
interacting with elements of the DOM. It's also leveraging an Amazon
RDS instance as a database for standard CRUD operations.

Note: This repository is currently a work in progress and will 
reflect the latter after due time.

## Requirements

1. go installed and at least go version go1.12.6


## Usage

1. Pull the package locally with `go get github.com/patalwell/fullStackGo`
2. Navigate to the root directory `fullStackGo` and issue the command `go run ./cmd/web`
3. A web service will start on port 8080 `http://localhost:8080`

Visit the driver to clarify which handler resolves to which subsequent HTTP request 
`/cmd/web/main.go`