/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as vec_map from './deps/sui/vec_map.js';
import * as vec_map_1 from './deps/sui/vec_map.js';
import * as vec_map_2 from './deps/sui/vec_map.js';
import * as vec_map_3 from './deps/sui/vec_map.js';
const $moduleName = '@local-pkg/2pc-mpc::support_config';
export const SupportConfig = new MoveStruct({ name: `${$moduleName}::SupportConfig`, fields: {
        /**
           * A nested map of supported curves to signature algorithms to hash schemes. e.g.
           * secp256k1 -> [(ecdsa -> [sha256, keccak256]), (schnorr -> [sha256])]
           */
        supported_curves_to_signature_algorithms_to_hash_schemes: vec_map.VecMap(bcs.u32(), vec_map_1.VecMap(bcs.u32(), bcs.vector(bcs.u32()))),
        /** List of paused curves in case of emergency (e.g. [secp256k1, ristretto]) */
        paused_curves: bcs.vector(bcs.u32()),
        /** List of paused signature algorithms in case of emergency (e.g. [ecdsa, schnorr]) */
        paused_signature_algorithms: bcs.vector(bcs.u32()),
        /** List of paused hash schemes in case of emergency (e.g. [sha256, keccak256]) */
        paused_hash_schemes: bcs.vector(bcs.u32()),
        /**
         * Signature algorithms that are allowed for global presign Deprecated: Use
         * GlobalPresignConfig instead.
         */
        signature_algorithms_allowed_global_presign: bcs.vector(bcs.u32())
    } });
export const GlobalPresignConfig = new MoveStruct({ name: `${$moduleName}::GlobalPresignConfig`, fields: {
        /**
           * Map of curves to signature algorithms for dWallets that are created via DKG.
           * This means for this curve and this signature algorithm, it is only allowed to
           * use global presign. e.g. secp256k1 -> [(ecdsa -> [sha256, keccak256]), (schnorr
           * -> [sha256])]
           */
        curve_to_signature_algorithms_for_dkg: vec_map_2.VecMap(bcs.u32(), bcs.vector(bcs.u32())),
        /**
         * Map of curves to signature algorithms for dWallets that are created via imported
         * key. This means for this curve and this signature algorithm, it is only allowed
         * to use global presign. e.g. secp256k1 -> [(ecdsa -> [sha256, keccak256]),
         * (schnorr -> [sha256])]
         */
        curve_to_signature_algorithms_for_imported_key: vec_map_3.VecMap(bcs.u32(), bcs.vector(bcs.u32()))
    } });