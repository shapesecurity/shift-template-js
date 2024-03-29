/**
 * Copyright 2018 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

let spec = require('shift-spec');

// TODO consider splitting these and the utilities from https://github.com/shapesecurity/shift-reducer-js/blob/es2016/scripts/lib/utilities.js into their own project
function isNodeOrUnionOfNodes(type) {
  return type.typeName === 'Union' && type.arguments.every(isNodeOrUnionOfNodes) || {}.hasOwnProperty.call(spec, type.typeName);
}

function isStatefulType(type) {
  switch (type.typeName) {
    case 'Enum':
    case 'String':
    case 'Number':
    case 'Boolean':
      return false;
    case 'Maybe':
    case 'List':
      return isStatefulType(type.argument);
    case 'Union':
      return type.arguments.some(isStatefulType);
    default:
      if (isNodeOrUnionOfNodes(type)) {
        return true;
      }
      throw new Error('unimplemented: type ' + type);
  }
}

module.exports = {
  isNodeOrUnionOfNodes,
  isStatefulType,
};
