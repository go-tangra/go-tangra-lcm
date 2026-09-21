# syntax=docker/dockerfile:1
# LCM service image: builds the Vue remote, embeds it (-tags ui), and produces a
# slim runtime carrying lcmsvc + the lcm-devca bootstrap tool. Build context is
# the repo root so the module's replace directives (../.. , ../auth, ../gateway)
# resolve.

FROM node:22-alpine AS ui
WORKDIR /ui
COPY services/lcm/ui/package.json services/lcm/ui/package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
COPY services/lcm/ui/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
COPY --from=ui /ui/dist ./services/lcm/ui/dist
WORKDIR /src/services/lcm
ENV CGO_ENABLED=0 GOFLAGS=-buildvcs=false
RUN go build -tags "ui" -o /out/lcmsvc ./cmd/lcmsvc \
 && go build -o /out/lcm-devca ./cmd/lcm-devca

FROM alpine:3.20
RUN apk add --no-cache ca-certificates postgresql-client && adduser -D -u 10001 app
COPY --from=build /out/lcmsvc /out/lcm-devca /usr/local/bin/
COPY services/lcm/deploy /app/deploy
WORKDIR /app
USER app
ENTRYPOINT ["lcmsvc"]
CMD ["-config", "deploy/dev.yaml"]
