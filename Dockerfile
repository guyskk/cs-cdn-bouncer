FROM python:3.10-slim
ADD ./ /app
WORKDIR /app
RUN python setup.py install
ENTRYPOINT [ "crowdsec-fastly-bouncer" ]