// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include "json_test_vectors.h"

UniValue
read_json(const std::string& jsondata)
{
    UniValue v;

    if (!(v.read(jsondata) && v.isArray()))
    {
        ADD_FAILURE();
        return UniValue(UniValue::VARR);
    }
    return v.get_array();
}
