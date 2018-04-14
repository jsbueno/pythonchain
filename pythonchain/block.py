from collections.abc import Sequence, Iterable, MutableSequence
from collections import OrderedDict
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

class BlockError(TransactionError):
    """Error on block verification"""


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
            output = BlockChain().get_output_from_input(self)
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

    def sign(self, wallet):
        private_key = ECC.import_key(bytes.fromhex(wallet.private_key))
        signer = DSS.new(private_key, 'fips-186-3')
        output = BlockChain().get_output_from_input(self)
        hash_ = SHA256.new(output.serialize())
        self.signature = int.from_bytes(signer.sign(hash_), "little")


class Transaction(base.Base):
    ID = base.UInt128()
    inputs = base.SequenceField(TransactionInput)
    outputs = base.SequenceField(TransactionOutput)
    signature = base.UInt512()
    transaction_type = base.UInt8()

    def __init__(self, **kwargs):
        kwargs.setdefault("ID", int(uuid.uuid4()))
        kwargs.setdefault("transaction_type", 0)  # 0 indicates normal transaction. 1 is for reward transaction
        self.blockchain = BlockChain()
        super().__init__(**kwargs)


    def get_fee(self):
        self.verify()
        if self.transaction_type == 1:
            # Reward transaction - balance comes out of thin air
            return 0
        bl = BlockChain()
        input_amount = sum(bl.get_output_from_input(inp).amount for inp in self.inputs)
        output_amount = sum(out.amount for out in self.outputs)

        if output_amount > input_amount:
            raise AmountError(f"Total fee is negative '{output_amount - input_amount}'")
        return input_amount - output_amount

    def verify(self):
        for input in self.inputs:
            input.verify()
        self.verify_transaction_signature()

    def verify_transaction_signature(self):
        if self.transaction_type == 1:
            return
        wallet = BlockChain().get_output_from_input(self.inputs[0]).wallet
        pubkey = ECC.import_key(bytes.fromhex(wallet))

        verifier = DSS.new(pubkey, "fips-186-3")

        signature = self.signature
        self.signature = 0
        hash_ = SHA256.new(self.serialize())
        self.signature = signature
        try:
            verifier.verify(hash_, signature.to_bytes(64, "little"))

        except ValueError as check_fail:
            raise SecretError("Invalid transaction signature")



    def sign_transaction(self, wallets):
        """
        Sign transaction with private key
        # based on https://github.com/adilmoujahid/blockchain-python-tutorial/blob/master/blockchain_client/blockchain_client.py
        """
        from .wallet import Wallet

        if isinstance(wallets, (Sequence, Iterable)):
            wallets = {wallet.public_key: wallet for wallet in wallets}
        elif isinstance(wallets, Wallet):
            wallets = {wallets.public_key: wallets}

        for input in self.inputs:
            output = BlockChain().get_output_from_input(input)
            try:
                input.sign(wallets[output.wallet])
            except KeyError as error:
                raise block.WalletError from error

        # Use the wallet used for the first input to sign the whole transaction
        if self.inputs:
            signer_wallet = BlockChain().get_output_from_input(self.inputs[0]).wallet
            wallet = wallets[signer_wallet]
        elif self.transaction_type == 1:  # we have input if we are a reward transaction
            wallet = next(iter(wallets.values()))
        else:
            raise TransactionError("Trying to sign transaction with no input")

        private_key = ECC.import_key(bytes.fromhex(wallet.private_key))
        signer = DSS.new(private_key, 'fips-186-3')
        self.signature = 0
        hash_ = SHA256.new(self.serialize())
        self.signature = int.from_bytes(signer.sign(hash_), "little")



class Block(base.Base):
    number = base.UInt32()
    previous_block = base.UInt256()
    transactions = base.SequenceField(Transaction)
    nonce = base.UInt128()
    difficulty = base.UInt256()

    def __init__(self, **kwargs):
        kwargs.setdefault("difficulty", registry["network_difficulty"])
        super().__init__(**kwargs)
        self.state = "new"

    def prepare(self):
        """Prepares block acording to current chain so
        that it gets ready to be mined.

        If no transactions have been manually added prior to calling
        this, will pick all transactions in the blockchain pool.
        """
        if not self.transactions:
            self.fetch_transactions()
        previous_block = BlockChain()[-1]
        self.previous_block = int.from_bytes(previous_block.hash(), "big")
        self.number = previous_block.number + 1
        self.make_reward()

    def fetch_transactions(self):
        bl = BlockChain()
        self.transactions.fill(bl.transaction_pool.values())

    def set_previous(self, block):
        self.previous_block = sha256(block.serialize()).digest()

    def make_reward(self):
        from .wallet import Wallet
        reward = registry["coin_reward"]
        target_wallet = registry["miner_public_key"]
        server_wallet = Wallet.from_data(registry["server_wallet"])

        fees = sum(transaction.get_fee() for transaction in self.transactions)
        out1 = TransactionOutput(wallet=target_wallet, amount=reward * TOKENMULTIPLIER, extra_data="Mining Reward")
        out2 = TransactionOutput(wallet=target_wallet, amount=fees, extra_data="Mining Fees")
        tr = Transaction()
        tr.transaction_type = 1  # Reward transaction
        tr.outputs.append(out1)
        tr.outputs.append(out2)
        tr.sign_transaction(server_wallet)
        self.transactions.append(tr)

    def check_difficulty(self):
        difficulty = (2 ** 256 - 1) // self.difficulty
        return int.from_bytes(self.hash(), "big") <= difficulty

    def hash(self):
        # This is what makes one "mining attempt"
        hash_ = SHA256.new(self.serialize())
        return hash_.digest()

    def __hash__(self):
        # Python coerces the return value of this to Int64
        return self.hash()

    def verify(self):
        first = True
        for transaction in reversed(self.transactions):
            if transaction.transaction_type == 1 and not first:
                raise BlockError("Reward transaction not as last of transactions list")
            transaction.verify()
            first = False
        if not self.check_difficulty():
            raise BlockError("Block hash do not match its set difficulty")


def mine_block(block):
    counter = 0
    while not block.check_difficulty():
        block.nonce = int(uuid.uuid4())

def create_block_zero():
    blockchain = BlockChain.__new__(BlockChain)
    blockchain.file = registry["blockchain_file"]
    blockchain.blocks = []

    # registry["blockchain"] = blockchain

    bl = Block()
    bl.difficulty = 1
    bl.number = 0
    tr = Transaction()
    tr.transaction_type = 1
    bl.previous_block = 0
    bl.make_reward()
    mine_block(bl)
    # Add block directly to internal data structure: skip verification
    # on blockchain.append code
    blockchain.blocks.append(bl)
    blockchain.last_read_block = -1
    blockchain.commit_unwriten_blocks()


class BlockChain(MutableSequence):
    """the blockchain
    """

    def __new__(cls, *args, **kwargs):
        # Singleton pattern - one blockchain per proccess.
        if "blockchain" in registry:
            return registry["blockchain"]
        self = super().__new__(cls, *args, **kwargs)
        registry["blockchain"] = self
        return self

    def __init__(self):
        # Avoid recursion on trying to get same instance.
        if hasattr(self, "bootstrapped"):
            return

        self.bootstrapped = True
        self.file = registry["blockchain_file"]
        self.blocks = []

        self.transaction_pool = {}

        # TODO: do not load all blockchain into memory
        # just scan to get the unspent transaction outputs and metadata
        self.load_blocks()
        self.verify()


    def add_transaction(self, transaction):
        """Adds a transaction to the transaction pool."""

        self.validate_inputs(transaction)
        transaction.verify()
        self.transaction_pool[transaction.ID] = transaction

    def validate_inputs(self, transaction):
        # check that all inputs are unsent in current blockchain state.
        inputs = {tr for tr in transaction.inputs}
        for past_transaction in self.all_transactions():
            for inp in past_transaction.inputs:
                if inp.transaction in inputs:
                    raise AlreadySpentError
        # TODO: check inputs against inputs in transactions in self.transaction_pool

    def all_transactions(self):
        # TODO: return transactions from all blocks in the chain
        return self.transactions.values()

    def get_output_from_input(self, input):
        try:
            inp_transaction = self.transactions[input.transaction]
            output = inp_transaction.outputs[input.index]
        except Exception as error:
            raise WalletError from error
        return output

    def load_blocks(self):
        with open(self.file, "rb") as file_:
            data = file_.read()
        self.blocks[:] = []
        offset = 0
        while offset < len(data):
            block = Block.from_data(data, offset)
            offset = block._offset
            self.blocks.append(block)
        self.last_read_block = self.blocks[-1].number
        self.load_transactions()

    def load_transactions(self):
        self.transactions = {}
        for block in self:
            for transaction in block.transactions:
                self.transactions[transaction.ID] = transaction

    def commit_unwriten_blocks(self):
        with open(self.file, "ab") as file_:
            for i,block in enumerate(self.blocks):
                block.verify()
                if block.number <= self.last_read_block:
                    continue
                if i:  # skip when writing block zero.
                    self.verify_block_in_chain(block, i - 1)
                file_.write(block.serialize())
        self.last_read_block = self.blocks[-1].number

    def verify_block_in_chain(self, block, previous_block_index=-1):
        previous_hash = int.from_bytes(self.blocks[previous_block_index].hash(), "big")
        if previous_hash != block.previous_block:
            raise BlockError("Previous block address don't match the one in chain")

    def verify(self):
        for i, block in enumerate(self.blocks):
            block.verify()
            if i:
                self.verify_block_in_chain(block, i - 1)

    def unspent_outputs(self, filter=None):
        outputs = {}
        for block in self:
            for transaction in block.transactions:
                outputs[transaction.ID] = local = OrderedDict()
                for i, output in enumerate(transaction.outputs):
                    local[i] = output
                for input in transaction.inputs:
                    try:
                        del outputs[input.transaction][input.index]
                    except (KeyError, IndexError) as error:
                        raise TransactionError(f"Invalid input for transaction {transaction.ID} found in chain")
        result = []
        for tr_id, transactions_local in outputs.items():
            for index, output in transactions_local.items():
                if not filter or output.wallet in filter:
                    result.append((tr_id, index, output))
        return result

    def __getitem__(self, index):
        return self.blocks[index]

    def __setitem__(self, index, value):
        raise RuntimeError("Can't change blocks on the chain")

    def __delitem__(self, index):
        raise RuntimeError("Can't change blocks on the chain")

    def __len__(self):
        return len(self.data)

    def insert(self, index, value):
        raise RuntimeError("Can't change blocks on the chain")

    def append(self, block):
        # TODO: verify
        self.verify_block_in_chain(block)
        self.blocks.append(block)

    def __repr__(self):
        return f"Blockchain with {len(self.blocks)} valid blocks"
