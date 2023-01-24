from typing import NewType

RegisterOffset = NewType("RegisterOffset", int)
TmpVar = NewType("TmpVar", int)

# This causes too much issues as a NewType, sot is a simple alias instead
# This means that is still legal to pass any str where a RegisterName is expected.
# The downside is that PyCharm will show the type as `str` when displaying the signature
RegisterName = str
