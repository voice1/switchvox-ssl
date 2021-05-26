# Switchvox SSL
Allows you to rapidly apply new SSL certificates to your Switchvox PBX installation.

This script was designed for internal use at VOICE1 to update our hosted client SSL certificates. It is idealy useful if you wish to:
- Update multiple Switchvox PBX systems
- Use Let's Encrypt SSL certificates (with the help of a cronjob)
- Automate your deployment workflow.

**ALWAYS TAKE A BACKUP FIRST**

> Depending on your specfic deployment, you may get a warning after updating the SSL certificate of 'You have 1 urgent notification. Click to view' 
> followed by a message of 'SSL Certificate Host Mismatch' This is common if you have phone networks defined using IP addresses, or if your hostname does not match your SSL certificate.

## Requirements
- python3 
- python requests
- loguru

## Usage

```
python add_ssl_certs.py --help
usage: add_ssl_certs.py [-h] [--key KEY] [--cert CERT] [--ca-bundle CA_BUNDLE]
                        [--ca-certs CA_CERTS] [--regcode REGCODE]
                        [--host HOST] [--username USERNAME]
                        [--password PASSWORD]
                        [--log-level {INFO,SUCCESS,WARNING,ERROR,CRITICAL,DEBUG,TRACE}]
                        {api,direct}

positional arguments:
  {api,direct}          For 'api' the api.switchvoxuc.com API will be used.
                        'direct' will connect to the switchvox directly.

optional arguments:
  -h, --help            show this help message and exit

SSL Certificates:
  --key KEY             Private key must be of type RSA. file or export
                        RSA_PRIVATE_KEY=
  --cert CERT           Issued Certificate. file or export X509_CERTIFICATE=
  --ca-bundle CA_BUNDLE
                        CA Bundle/ intermediate cert. file or export
                        INTERMEIDATE_CA_CERTIFICATE=
  --ca-certs CA_CERTS   List of CA certs. (Not usually required)

Hosts:
  --regcode REGCODE     Switchvox 6 char regcode. Required for 'api' mode.
  --host HOST           Hostname
  --username USERNAME   username
  --password PASSWORD   password

Logging:
  --log-level {INFO,SUCCESS,WARNING,ERROR,CRITICAL,DEBUG,TRACE}
                        Set log level
```

It is recomended that you set your shell enviorment variables to the file path of your SSL Certificate.
```
export RSA_PRIVATE_KEY=/path/to/ssl_cert/switchvoxuc.key
export X509_CERTIFICATE=/path/to/ssl_cert/switchvoxuc.crt
export INTERMEIDATE_CA_CERTIFICATE=/path/to/ssl_cert/switchvoxuc.ca.crt
```
Optinally you may specify the file path directly using command line arguments.
> If you want to use Let's Encrypt SSL certificates, you can use this option as part of a cronjob when new certificates are generated.

## Example

> You should use the 'direct' mode.

Using shell variables.
```
export RSA_PRIVATE_KEY=/path/to/ssl_cert/switchvoxuc.key
export X509_CERTIFICATE=/path/to/ssl_cert/switchvoxuc.crt
export INTERMEIDATE_CA_CERTIFICATE=/path/to/ssl_cert/switchvoxuc.ca.crt
python add_ssl_certs.py direct --host 192.168.10.60 --username admin --password "Your$uper3a$$w0rD"
```
Using file paths
```
python add_ssl_certs.py direct --host 192.168.10.60 --username admin --password "Your$uper3a$$w0rD" \
--key /path/to/ssl_cert/switchvoxuc.key \
--cert /path/to/ssl_cert/switchvoxuc.crt \
--ca-bundle /path/to/ssl_cert/switchvoxuc.ca.crt
```
### Success fully added
```
2021-05-26 15:12:38.902 | INFO     | __main__:<module>:161 - Using ENV Variables for certificates.
2021-05-26 15:12:38.902 | INFO     | __main__:make_params:111 - Loading certificates
2021-05-26 15:12:38.903 | INFO     | __main__:update_ssl:64 - Using mode: 'direct'
2021-05-26 15:12:48.900 | INFO     | __main__:update_ssl:78 - POST https://192.168.10.60/json 200 OK - {
   "response" : {
      "transaction_id" : "sslUpdate",
      "method" : "switchvox.network.ssl.update",
      "result" : {
         "progress" : {
            "id" : "gklwxwyxktbseaqd"
         }
      }
   }
}
```

### Sample of error
```
2021-05-26 14:56:27.107 | INFO     | __main__:<module>:155 - Using ENV Variables for certificates.
2021-05-26 14:56:27.107 | INFO     | __main__:make_params:108 - Loading certificates
2021-05-26 14:56:27.107 | INFO     | __main__:update_ssl:61 - Using mode: 'direct'
2021-05-26 14:56:27.221 | INFO     | __main__:update_ssl:75 - POST https://192.168.10.60/json 200 OK - {
   "response" : {
      "errors" : {
         "error" : {
            "message" : "Your json request is not structured correctly.",
            "code" : "74151"
         }
      }
   }
}
```

# DISLAIMER
This script uses an undocumented API calls and may change in the future. That being said, the standard disclaimer applies.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
