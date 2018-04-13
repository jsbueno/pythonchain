from collections.abc import Sequence, Iterable

import Crypto
import Crypto.Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


from pythonchain import base
from pythonchain import block
from pythonchain.runtime import registry




class Wallet(base.Base):
    public_key = base.String()
    private_key = base.String()

    def __init__(self, **kwargs):
        if not kwargs:
            kwargs.update(self.new_keys())
        super().__init__(**kwargs)

    def new_keys(self):
        private_key = ECC.generate(curve="P-256")
        public_key = private_key.public_key()

        response = {
            'private_key': private_key.export_key(format='DER').hex(),
            'public_key': public_key.export_key(format='DER').hex()
        }

        return response


    def sign_transaction_input(self, input, output=None):
        private_key = ECC.import_key(bytes.fromhex(self.private_key))
        signer = DSS.new(private_key, 'fips-186-3')
        output = output or registry["blockchain"].get_output_from_input(input)
        hash_ = SHA256.new(output.serialize())
        input.signature = int.from_bytes(signer.sign(hash_), "little")


def sign_transaction(transaction, wallets):
    if isinstance(wallets, (Sequence, Iterable)):
        wallets = {wallet.public_key: wallet for wallet in wallets}
    elif isinstance(wallets, Wallet):
        wallets = {wallets.public_key: wallets}

    for input in transaction.inputs:
        output = registry["blockchain"].get_output_from_input(input)
        try:
            wallets[output.wallet].sign_transaction_input(input, output)
        except KeyError as error:
            raise block.WalletError from error

