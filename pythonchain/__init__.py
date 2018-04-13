from .runtime import registry
from . import block

registry["blockchain"] = block.BlockChain()
