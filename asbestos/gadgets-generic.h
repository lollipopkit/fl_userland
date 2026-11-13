#include "cpu-offsets.h"

# The host is Apple, whose C symbols carry a leading underscore.
#
# This file used to carry the i386 backend's gadget tables -- `ifin`,
# `REG_LIST`, `GADGET_LIST`, `SIZE_LIST`, `.gadget_list` and `.gadget_array`
# -- and a Linux branch for every directive. Nothing in the AArch64 set used
# any of it.
#define NAME(x) _##x

# vim: ft=gas
