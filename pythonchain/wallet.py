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
        partial_balance = 0
        to_use = []
        for output in outputs:
            partial_balance += output[2].amount
            to_use.append(output)
            if partial_balance >= (amount + fee):
                break
        else:
            raise ValueError("No single unspent output have this much money")
        inputs=[]
        for output in to_use:
            ti = block.TransactionInput()
            ti.transaction = output[0]
            ti.index = output[1]
            inputs.append(ti)
        to1 = block.TransactionOutput()
        to1.wallet = target.public_key if isinstance(target, Wallet) else target
        to1.amount = amount

        change = partial_balance - amount - fee
        to2 = block.TransactionOutput()
        to2.wallet = self.public_key
        to2.amount = change

        tr = block.Transaction()
        tr.inputs.extend(inputs)
        tr.outputs.extend([to1, to2])
        tr.sign_transaction(self)
        return tr

