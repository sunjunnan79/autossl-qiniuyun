FROM golang:1.24.4 AS builder

COPY . /src

WORKDIR /src/
RUN go mod tidy

RUN GOPROXY=https://goproxy.cn go build -o /src/main .

FROM debian:bookworm-slim

ENV TZ=Asia/Shanghai

RUN set -xe; \
    echo 'deb http://mirrors.tuna.tsinghua.edu.cn/debian bookworm main' > /etc/apt/sources.list; \
    echo 'deb http://mirrors.tuna.tsinghua.edu.cn/debian bookworm-updates main' >> /etc/apt/sources.list; \
    echo 'deb http://mirrors.tuna.tsinghua.edu.cn/debian-security bookworm-security main' >> /etc/apt/sources.list; \
    \
    rm -f /etc/apt/sources.list.d/*; \
    # 执行 APT 命令
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates netbase; \
    \
    # 清理
    rm -rf /var/lib/apt/lists/*; \
    apt-get autoremove -y; \
    apt-get autoclean -y;


COPY --from=builder /src/main /app/main

WORKDIR /app

CMD ["./main"]