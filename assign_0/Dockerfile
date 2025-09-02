# Use the latest GCC image as the base
FROM gcc:latest

# Set the working directory to HW0 (assumes the Dockerfile is in the root of the repository)
WORKDIR /HW0

# Copy all files in the HW0 directory into the container
COPY HW0 /HW0

# Install OpenSSL library for SHA256 support
RUN apt-get update && apt-get install -y libssl-dev

# Compile the C program
RUN gcc -o HomeWork0 homework0.c -lssl -lcrypto

# Run the compiled program
CMD ["./HomeWork0"]
