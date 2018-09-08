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

let { reduce, adapt } = require('shift-reducer');

let LazyCheckedCloneReducer = require('./lazy-checked-clone.js');

module.exports = function replace(tree, getReplacement) {
  // getReplacement signals that it is not attempting to replace a given node by returning `undefined`. If it returns `null`, that's treated as an attempt to replace a Just(node) with a Nothing.
  let adapted = adapt((newNode, originalNode) => {
    let replacement = getReplacement(newNode, originalNode);
    if (typeof replacement !== 'undefined') {
      return replacement;
    }
    return newNode;
  }, new LazyCheckedCloneReducer);
  return reduce(adapted, tree);
};
