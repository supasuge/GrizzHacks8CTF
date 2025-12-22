FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --production

COPY . .

RUN node scripts/generate-keys.js && \
    node scripts/generate-samples.js

EXPOSE 3000

ENV NODE_ENV=production
ENV FLAG=GRIZZ{p4ck3t_d3sync_auth_byp4ss_CVE_2025_47934}

CMD ["node", "server.js"]
