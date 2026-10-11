FROM kalilinux/kali-rolling

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    git strace ltrace radare2 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /rekit

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --break-system-packages -r requirements.txt
RUN pip install --break-system-packages -e .

# Default command
CMD ["rekit"]
