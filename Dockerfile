FROM alpine:3.16 AS build_deps

RUN apk add --no-cache --update nodejs npm openjdk11 go
RUN npm install @openapitools/openapi-generator-cli -g

WORKDIR /workspace

COPY pkg pkg
COPY stackpath-oas stackpath-oas
COPY go.mod .
COPY go.sum .
COPY main.go .

RUN for i in \
	accounts_and_users dns; \
	do \
		openapi-generator-cli generate -g go --api-package pkg/$i \
			-i stackpath-oas/$i.json -o pkg/$i \
			--package-name $i \
			--additional-properties enumClassPrefix=true,isGoSubmodule=true; \
		rm -f ./pkg/$i/go.mod; \
		rm -f ./pkg/$i/go.sum; \
	done || exit 1

RUN go mod download

FROM build_deps AS build

RUN CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM alpine:3.16

RUN apk add --no-cache ca-certificates

COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
