// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

#ifndef HUSH_JOINSPLIT_H_
#define HUSH_JOINSPLIT_H_

#include "Zcash.h"
#include "Proof.hpp"
#include "Address.hpp"
#include "Note.hpp"
#include "IncrementalMerkleTree.hpp"
#include "NoteEncryption.hpp"
#include "uint256.h"
#include "uint252.h"
#include <array>

namespace libzcash {

static constexpr size_t GROTH_PROOF_SIZE = (
    48 + // π_A
    96 + // π_B
    48); // π_C

typedef std::array<unsigned char, GROTH_PROOF_SIZE> GrothProof;
typedef boost::variant<PHGRProof, GrothProof> SproutProof;
class JSInput { };
class JSOutput { };
template<size_t NumInputs, size_t NumOutputs>
class JoinSplit { };

}

typedef libzcash::JoinSplit<HUSH_NUM_JS_INPUTS, HUSH_NUM_JS_OUTPUTS> ZCJoinSplit;

#endif // HUSH_JOINSPLIT_H_
