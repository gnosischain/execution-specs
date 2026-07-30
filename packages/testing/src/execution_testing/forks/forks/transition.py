"""List of all transition fork definitions."""

from ..transition_base_fork import TransitionBaseClass, transition_fork
from .forks import (
    BPO2,
    BPO3,
    BPO4,
    Amsterdam,
    Berlin,
    Cancun,
    London,
    Osaka,
    Paris,
    Prague,
    Shanghai,
)


# Transition Forks
@transition_fork(to_fork=London, from_fork=Berlin, at_block=5)
class BerlinToLondonAt5(TransitionBaseClass):
    """Berlin to London transition at Block 5."""

    pass


@transition_fork(to_fork=Shanghai, from_fork=Paris, at_timestamp=15_000)
class ParisToShanghaiAtTime15k(TransitionBaseClass):
    """Paris to Shanghai transition at Timestamp 15k."""

    pass


@transition_fork(to_fork=Cancun, from_fork=Shanghai, at_timestamp=15_000)
class ShanghaiToCancunAtTime15k(TransitionBaseClass):
    """Shanghai to Cancun transition at Timestamp 15k."""

    pass


@transition_fork(to_fork=Prague, from_fork=Cancun, at_timestamp=15_000)
class CancunToPragueAtTime15k(TransitionBaseClass):
    """Cancun to Prague transition at Timestamp 15k."""

    pass


@transition_fork(to_fork=Osaka, from_fork=Prague, at_timestamp=15_000)
class PragueToOsakaAtTime15k(TransitionBaseClass):
    """Prague to Osaka transition at Timestamp 15k."""

    pass


@transition_fork(to_fork=Amsterdam, from_fork=Osaka, at_timestamp=15_000)
class OsakaToAmsterdamAtTime15k(TransitionBaseClass):
    """Osaka to Amsterdam transition at Timestamp 15k."""

    pass


@transition_fork(to_fork=BPO3, from_fork=BPO2, at_timestamp=15_000)
class BPO2ToBPO3AtTime15k(TransitionBaseClass):
    """BPO2 to BPO3 transition at Timestamp 15k."""

    pass


@transition_fork(to_fork=BPO4, from_fork=BPO3, at_timestamp=15_000)
class BPO3ToBPO4AtTime15k(TransitionBaseClass):
    """BPO3 to BPO4 transition at Timestamp 15k."""

    pass
