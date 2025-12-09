# Build the manager binary
FROM golang:1.21 AS builder

WORKDIR /workspace

# Copy go mod files
COPY go.mod go.mod
COPY go.sum go.sum

# Copy the entire project (needed for local package references)
COPY . .

# Build the operator
WORKDIR /workspace/deploy/operator
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o manager main.go

# Use distroless as minimal base image
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/deploy/operator/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
