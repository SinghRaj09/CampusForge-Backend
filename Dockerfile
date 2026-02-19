FROM ubuntu:22.04

# Install dependencies
RUN apt update && apt install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install CPR
RUN git clone https://github.com/libcpr/cpr.git && \
    cd cpr && \
    mkdir build && cd build && \
    cmake .. -DCPR_USE_SYSTEM_CURL=ON && \
    make -j$(nproc) && \
    make install

# Set working directory
WORKDIR /app

# Copy backend files
COPY . .

# Build backend
RUN mkdir build && cd build && \
    cmake .. && \
    make -j$(nproc)

EXPOSE 18080

CMD ["./build/CampusConnect"]
