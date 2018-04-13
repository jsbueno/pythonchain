import itertools
import uuid

import Crypto
import Crypto.Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


from pythonchain import base
from pythonchain.runtime import registry

TOKENMULTIPLIER = 100000000  # 100 million

class TransactionError(Exception):
    """Base Blockchain Exception"""


class InvalidOutputReferenceError(TransactionError):
    """Tried to use invalid output in a transaction"""


class SecretError(TransactionError):
    """Error in signature checking"""


class WalletError(TransactionError):
    """Error in wallet used"""


class AlreadySpentError(TransactionError):
    """Trying to use spent transaction in new transaction"""

class AmountError(TransactionError, ValueError):
    """Used when there is an error in the values"""


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


class TransactionOutput(base.Base):
    ID = base.UInt128()
    wallet = base.String()
    amount = base.UInt64()
    extra_data = base.String()

    def __init__(self, **kwargs):
        kwargs.setdefault("ID", int(uuid.uuid4()))
        super().__init__(**kwargs)


class TransactionInput(base.Base):
    transaction = base.UInt128()
    index = base.UInt16()
    signature = base.UInt512()

    def verify(self):

        try:
            output = registry["blockchain"].get_output_from_input(self)
            pubkey = ECC.import_key(bytes.fromhex(output.wallet))
        except Exception as error:
            raise InvalidOutputReferenceError from error

        verifier = DSS.new(pubkey, "fips-186-3")
        # privkey = ECC.import_key(key)
        # signer = DSS.new(privkey, "fips-186-3")

        hash_ = SHA256.new(output.serialize())
        try:
            verifier.verify(hash_, self.signature.to_bytes(64, "little"))

        except ValueError as check_fail:
            raise SecretError from check_fail


class Transaction(base.Base):
    ID = base.UInt128()
    inputs = base.SequenceField(TransactionInput)
    outputs = base.SequenceField(TransactionOutput)
    signature = base.UInt512()

    def __init__(self, **kwargs):
        kwargs.setdefault("ID", int(uuid.uuid4()))
        self.blockchain = registry["blockchain"]
        super().__init__(**kwargs)


    def get_fee(self):

        self.verify()
        bl = registry["blockchain"]
        input_amount = sum(bl.get_output_from_input(inp).amount for inp in self.inputs)
        output_amount = sum(out.amount for out in self.outputs)

        if output_amount > input_amount:
            raise AmountError(f"Total fee is negative '{output_amount - input_amount}'")
        return input_amount - output_amount

    def verify(self):
        for input in self.inputs:
            input.verify()

    def sign_transaction(self, private_key):
        """
        Sign transaction with private key
        # based on https://github.com/adilmoujahid/blockchain-python-tutorial/blob/master/blockchain_client/blockchain_client.py
        """
        private_key = ECC.import_key(bytes.fromhex(private_key))
        signer = DSS.new(private_key, 'fips-186-3')

        self.signature = 0
        h = SHA256.new(self.serialize())
        self.signature = int.from_bytes(signer.sign(h), "little")




class BlockChain:
    def __init__(self):
        self.transactions = {}
        self.spent_transactions = {}
        self.transaction_pool = {}
        # self.blockchain_instance = register["blockchain_instance"]

    def add_transaction(self, transaction):
        self.validate_inputs(transaction)
        self.transaction_pool[transaction.ID] = transaction

    def validate_inputs(transaction):
        # check that all inputs are unsent in current blockchain state.
        inputs = {tr.ID for id in transaction.inputs}
        for past_transaction in self.all_transactions():
            for inp in past_transactions.inputs:
                if inp.transaction in inputs:
                    raise AlreadySpentError

    def get_transaction(self, id):
        try:
            return self.transactions[id]
        except KeyError:
            return self.fetch_transaction(id)

    def fetch_transaction(self, id):
        raise NotImplementedError

    def all_transactions(self):
        # TODO: return transactions from all blocks in the chain
        return self.transactions.values()

    def get_output_from_input(self, input):
        try:
            inp_transaction = self.get_transaction(input.transaction)
            output = inp_transaction.outputs[input.index]
        except Exception as error:
            raise WalletError from error
        return output
