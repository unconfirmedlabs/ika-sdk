/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from '../../../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
const $moduleName = 'ika_common::system_object_cap';
export const SystemObjectCap = new MoveStruct({ name: `${$moduleName}::SystemObjectCap`, fields: {
        id: bcs.Address
    } });