#! /bin/sh

# This part creates a TCP connection to the specified address (127.0.0.1) and port (9000).
# It assigns this connection to file descriptor 3. Using a file descriptor allows the shell to
# treat the network connection like a regular file, enabling it to read from and write to it.
exec 3<>/dev/tcp/127.0.0.1/9000;

# This sends an HTTP GET request to the /health/ready endpoint. The -e flag in echo enables
# the interpretation of backslash escapes, allowing for the correct use of carriage returns (\r)
# and newlines (\n) to form a valid HTTP request header.
# The >&3 redirects the output of the echo command to the network connection (file descriptor 3).
echo -e 'GET /auth/health/ready HTTP/1.1\r\nHost: localhost:9000\r\nConnection: close\r\n\r\n' >&3;

# This part reads the HTTP response from the network connection and searches for a specific string.
# If found exits normally otherwise non-zero exit code i.e failure code of 1
cat <&3 | grep -q '\"status\": \"UP\"' && exit 0 || exit 1