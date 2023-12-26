// Copyright (c) 2021-2023 The Hush developers
// Copyright (c) 2020-2023 The Freicoin Developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef HUSH_STRATUM_H
#define HUSH_STRATUM_H

/** Configure the stratum server. */
bool InitStratumServer();

/** Interrupt the stratum server connections. */
void InterruptStratumServer();

/** Cleanup stratum server network connections and free resources. */
void StopStratumServer();

#endif // HUSH_STRATUM_H

// End of File
