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
    public_key = base.ShortString()
    private_key = base.ShortString()

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

    def balance(self, format=True):
        value = sum(output.amount for tr_id, index, output in block.BlockChain().unspent_outputs(filter=self.public_key))
        if format:
            return f"{value/block.TOKENMULTIPLIER:.02f}"
        return value

    def simple_transaction(self, target, amount, fee=0):
        bl = block.BlockChain()
        outputs = bl.unspent_outputs(filter=self.public_key)
        for output in outputs:
            if output[2].amount >= (amount + fee):
                break
        else:
            raise ValueError("No single unspent output have this much money")
        ti = block.TransactionInput()
        ti.transaction = output[0]
        ti.index = output[1]
        to1 = block.TransactionOutput()
        to1.wallet = target.public_key if isinstance(target, Wallet) else target
        to1.amount = amount

        change = output[2].amount - amount - fee
        to2 = block.TransactionOutput()
        to2.wallet = self.public_key
        to2.amount = change

        tr = block.Transaction()
        tr.inputs.append(ti)
        tr.outputs.extend([to1, to2])
        tr.sign_transaction(self)
        return tr

