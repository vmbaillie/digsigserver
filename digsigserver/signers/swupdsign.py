import shutil
import os
from digsigserver.signers import Signer
from sanic import Sanic


class SwupdateSigner(Signer):
    keytag = 'swupdate'

    def __init__(self, app: Sanic, workdir: str, distro: str):
        signcmd = shutil.which('openssl')
        if not signcmd:
            raise RuntimeError('no openssl command')
        self.signcmd = signcmd
        super().__init__(app, workdir, distro)

    def sign(self, method: str, sw_description: str, outfile: str, keylabel: str) -> bool:
        if method == "RSA":
            privkey = self.keys.get('rsa-private.key')
            if not privkey:
                raise RuntimeError('RSA private key missing for swupdate signing')
            cmd = [self.signcmd, 'dgst', '-sha256', '-sign', privkey, '-out', outfile, sw_description]
        elif method == "CMS":
            cms_cert = self.keys.get('cms.cert')
            cms_key = self.keys.get('cms-private.key')
            if not cms_cert or not cms_key:
                raise RuntimeError('CMS cert or private key missing for swupdate signing')
            cmd = [self.signcmd, 'cms', '-sign', '-in', sw_description, '-out', outfile,
                   '-signer', cms_cert, '-inkey', cms_key, '-outform', 'DER',
                   '-nosmimecap', '-binary']
        elif method == "RSA-HSM":
            pin = os.environ.get('YUBIHSM_PASSWORD')
            cmd = [ "pkcs11-tool", "--module", "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so", "--sign",
                    "--label", keylabel, "--mechanism", "SHA256-RSA-PKCS",
                    "--input-file", sw_description, "--output-file", outfile,
                    "--pin", pin ]

        else:
            raise RuntimeError('Unrecognized signing method {} - must be RSA or CMS'.format(method))

        return self.run_command(cmd)
