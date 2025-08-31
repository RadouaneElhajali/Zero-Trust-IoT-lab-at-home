# Use a minimal, modern Debian base image
FROM debian:bookworm-slim

# Install OpenSSL and the ca-certificates package
RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /ca

# This command just keeps the container running so we can use it
CMD ["tail", "-f", "/dev/null"]
