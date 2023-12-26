// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include "JoinSplit.hpp"
#include "prf.h"
#include "sodium.h"
#include <memory>
#include <fstream>
#include "librustzcash.h"

namespace libzcash {

template<size_t NumInputs, size_t NumOutputs>
class JoinSplitCircuit : public JoinSplit<NumInputs, NumOutputs> {
public:
    JoinSplitCircuit() {}
    ~JoinSplitCircuit() {}
};
}
