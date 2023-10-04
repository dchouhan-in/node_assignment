FROM node:14


RUN mkdir -p /opt/backend

WORKDIR /opt/backend/

COPY app /opt/backend/app

COPY package.json /opt/backend/

RUN npm install

EXPOSE 3000

CMD ["node", "app/main.js"]