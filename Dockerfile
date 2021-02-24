FROM golang:alpine as builder

# Set necessary environmet variables needed for our image
ENV GO111MODULE=on

# Move to working directory /build
WORKDIR /build

# Copy and download dependency using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Build the application
RUN go build -o main .

FROM alpine

WORKDIR /app

# Copy binary from build to main folder
COPY --from=builder /build/main .

# Export necessary port
EXPOSE 25

# Command to run when starting the container
CMD ["/app/main"]