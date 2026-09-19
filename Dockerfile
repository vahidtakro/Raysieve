# raysieve — minimal image with proxy cores pre-baked.
FROM node:22-alpine

WORKDIR /opt/raysieve
COPY package.json README.md LICENSE ./
COPY bin ./bin
COPY src ./src
COPY examples ./examples
COPY test ./test

ENV RAYSIEVE_BIN_DIR=/opt/raysieve/.cache-bin
RUN mkdir -p /opt/raysieve/.cache-bin && \
    node -e "import('./src/core-download.js').then(m => Promise.all([m.ensureCore('xray'), m.ensureCore('sing-box')])).then(() => console.log('cores baked into image'))"

WORKDIR /work
ENTRYPOINT ["node", "/opt/raysieve/bin/raysieve.js"]
CMD ["--help"]
