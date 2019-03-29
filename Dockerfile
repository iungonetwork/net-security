FROM node:10 as builder
COPY . /app
WORKDIR /app
RUN npm install

FROM node:10-alpine
COPY --from=builder /app /app
WORKDIR /app
CMD ["node", "/app/src/main.js"]