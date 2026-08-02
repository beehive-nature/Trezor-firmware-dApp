/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "librust.h"
#include "py/runtime.h"

#if MICROPY_PY_TREZORUI_API
MP_REGISTER_MODULE(MP_QSTR_trezorui_api, mp_module_trezorui_api);
#endif

#if MICROPY_PY_TREZORPROTO
MP_REGISTER_MODULE(MP_QSTR_trezorproto, mp_module_trezorproto);
#endif

#if MICROPY_PY_TREZORTRANSLATE
MP_REGISTER_MODULE(MP_QSTR_trezortranslate, mp_module_trezortranslate);
#endif

#ifdef USE_BLE
MP_REGISTER_MODULE(MP_QSTR_trezorble, mp_module_trezorble);
#endif

#ifdef USE_THP
MP_REGISTER_MODULE(MP_QSTR_trezorthp, mp_module_trezorthp);
#endif

// #if, not #ifdef. SConscript.firmware emits USE_MONERO as '1' or '0' rather than
// defining/omitting it, so #ifdef is satisfied by both and this registration fired in
// every build — including bitcoin-only, where the Rust symbol is not compiled. The
// QSTR collector greps ^MP_REGISTER_MODULE and emits a table entry taking the symbol's
// address, so that was a hard link dependency on something that did not exist.
// crypto/monero/monero.h:8 and crypto/options.h:91 use #if for the same reason.
#if USE_MONERO
MP_REGISTER_MODULE(MP_QSTR_trezorzano, mp_module_trezorzano);
#endif

#if defined(TREZOR_EMULATOR) && PYOPT == 0
MP_REGISTER_MODULE(MP_QSTR_coveragedata, mp_module_coveragedata);
#endif

#if defined(USE_DBG_CONSOLE)
MP_REGISTER_MODULE(MP_QSTR_trezorlog, mp_module_trezorlog);
#endif
