FROM python:3.7

# Flask will listen on port 5000
EXPOSE 5000

WORKDIR /ca

COPY requirements.txt /ca
RUN pip3 install -r requirements.txt

COPY ./app /ca

# Password for CA private key
ENV CA_PASS=1234

CMD python3 issuer.py
