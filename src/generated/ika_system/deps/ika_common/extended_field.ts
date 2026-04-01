/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from '../../../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
const $moduleName = 'ika_common::extended_field';
export const ExtendedField = new MoveStruct({ name: `${$moduleName}::ExtendedField<phantom T>`, fields: {
        id: bcs.Address
    } });