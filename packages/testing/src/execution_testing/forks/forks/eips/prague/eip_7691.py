"""
EIP-7691: Blob throughput increase.

Increase the number of blobs to reach a new target and max of 6 and 9
blobs per block respectively.

https://eips.ethereum.org/EIPS/eip-7691
"""

from ....base_fork import BaseFork


class EIP7691(
    BaseFork,
    update_blob_constants={
        "MAX_BLOBS_PER_BLOCK": 2,
        "TARGET_BLOBS_PER_BLOCK": 1,
        "BLOB_BASE_FEE_UPDATE_FRACTION": 1112826,
    },
):
    """EIP-7691 class."""

    pass
