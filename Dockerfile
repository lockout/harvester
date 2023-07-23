# syntax=docker/dockerfile:1

FROM python:alpine

RUN apk -U upgrade
RUN apk add --no-cache \
        xvfb \
        chromium \
        chromium-chromedriver \
        tor

RUN mkdir /harvester
WORKDIR /harvester
COPY container .
RUN chmod +xxx harvester.py
RUN mkdir log rep

RUN pip install --upgrade pip
RUN pip install -r dependencies