FROM golang:1-alpine as builder
ENV CGO_ENABLED=0

RUN apk --no-cache update && apk --no-cache upgrade

WORKDIR /var/build
RUN adduser -u 586 --disabled-password builder && chown -R builder /var/build

COPY --chown=builder . /var/build

USER builder
RUN go build -ldflags "-s -w" -o eleos main.go


FROM gcr.io/distroless/static-debian12

COPY --from=builder --chown=root /var/build/eleos /var/app/eleos

USER 589

CMD ["/var/app/eleos"]