FROM node:17.3.0 as dependencies

WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile

FROM node:17.3.0 as builder
WORKDIR /app
COPY . .
COPY --from=dependencies /app/node_modules ./node_modules

EXPOSE 3000
CMD ["yarn", "dev"]