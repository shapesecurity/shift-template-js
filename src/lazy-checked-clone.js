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

// TODO consider generating this file

// compare https://github.com/shapesecurity/shift-reducer-js/blob/dda9f5105b3a08e6ac070c2bd5361e44ca224fd3/scripts/build/generate-lazy-clone-reducer.js

let spec = require('shift-spec').default;
let Shift = require('shift-ast/checked');


// TODO consider splitting these and the utilities from https://github.com/shapesecurity/shift-reducer-js/blob/es2016/scripts/lib/utilities.js into their own project
function isNodeOrUnionOfNodes(type) {
  return type.typeName === 'Union' && type.arguments.every(isNodeOrUnionOfNodes) || spec.hasOwnProperty(type.typeName);
}

function equals(type, a, b) {
  switch (type.typeName) {
    case 'Enum':
    case 'String':
    case 'Number':
    case 'Boolean':
      throw new Error('not reached');
    case 'List':
      switch (type.argument.typeName) {
        case 'Enum':
        case 'String':
        case 'Number':
        case 'Boolean':
          throw new Error('not reached');
        case 'List':
          throw new Error('unimplemented: lists of lists');
        case 'Maybe':
          if (isNodeOrUnionOfNodes(type.argument.argument)) {
            return a.length === b.length && a.every((v, i) => v === b[i]);
          }
          throw new Error('unimplemented: list of maybe of ' + type.argument.argument);
        default:
          if (isNodeOrUnionOfNodes(type.argument)) {
            return a.length === b.length && a.every((v, i) => v === b[i]);
          }
          throw new Error('unimplemented: list of ' + type.argument);
      }
    case 'Maybe':
      if (isNodeOrUnionOfNodes(type.argument)) {
        return a === b;
      }
      throw new Error('unimplemented: maybe of ' + type.argument);
    default:
      if (isNodeOrUnionOfNodes(type)) {
        return a === b;
      }
      throw new Error('unimplemented: ' + type);
  }
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


class LazyCheckedCloneReducer {}

// TODO replace loop with `LazyCheckedCloneReducer.prototype = Object.fromEntries(Object.entries(spec).map(...))`
for (let typeName of Object.keys(spec)) {
  let type = spec[typeName];
  let statefulFields = type.fields.filter(f => f.name !== 'type' && isStatefulType(f.type));
  LazyCheckedCloneReducer.prototype['reduce' + typeName] =
    statefulFields.length === 0
      ? node => node
      : (node, data) =>
        statefulFields.every(f => equals(f.type, node[f.name], data[f.name]))
          ? node
          : new Shift[typeName](type.fields.reduce(
            (acc, f) => {
              if (f.name === 'type') {
                return acc;
              }
              acc[f.name] = isStatefulType(f.type) ? data[f.name] : node[f.name];
              return acc;
            }, {}
          )); // TODO Object.fromEntries, damn it
}

module.exports = LazyCheckedCloneReducer;
