# Benchmark fixture: intentionally-misconfigured Dockerfile.
# DO NOT docker build for production use.
# Expected check IDs:
#   - DS-0001 :latest tag
#   - DS-0002 image user should not be root
#   - DS-0013 ADD with remote URL
#   - DS-0026 no HEALTHCHECK defined
FROM alpine:latest
RUN apk add --no-cache curl
ADD https://example.com/setup.sh /opt/setup.sh
USER root
CMD ["/opt/setup.sh"]
