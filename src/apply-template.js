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

let { parseScriptWithLocation, parseModuleWithLocation } = require('shift-parser');

let defaultMatcher = require('./default-matcher.js');
let findNodes = require('./find-nodes.js');
let replace = require('./replace.js');


module.exports = function applyTemplate(src, newNodes, { matcher = defaultMatcher, isModule = false } = {}) {
  // for now, newNodes is an object { [name]: node => node }
  // TODO allow other types: fn, string-keyed map

  let { tree, locations, comments } = (isModule ? parseModuleWithLocation : parseScriptWithLocation)(src);
  let names = findNodes({ tree, locations, comments }, { matcher });
  let nodeToName = new Map(names.map(({ name, node }) => [node, name]));

  let getReplacement = (newNode, originalNode) => nodeToName.has(originalNode) ? newNodes[nodeToName.get(originalNode)](newNode) : void 0;


  // Begin sanity checks
  let foundNames = new Set(names.map(({ name }) => name));
  let providedNames = new Set(Object.keys(newNodes));

  if (nodeToName.size < names.length) {
    // We have a node with multiple names: find it so we can produce a useful error message, then throw
    // TODO we could just apply the transformation functions several times in sequence, I guess. Useful for annotation-alikes.
    for (let { name, node } of names) {
      if (nodeToName.get(node) !== name) {
        throw new TypeError(`One node has two names: ${name} and ${nodeToName.get(node)}`);
      }
    }
    throw new Error('unreachable');
  }

  let extraNames = [...providedNames].filter(name => !foundNames.has(name));
  if (extraNames.length > 0) {
    throw new TypeError(`Provided replacements for nodes named ${extraNames.map(name => `"${name}"`).join(', ')}, but no corresponding nodes were found`);
  }
  let missingNames = [...foundNames].filter(name => !providedNames.has(name));
  if (missingNames.length > 0) {
    throw new TypeError(`Found nodes named ${missingNames.map(name => `"${name}"`).join(', ')}, but no corresponding replacements were provided`);
  }
  // End sanity checks

  return replace(tree, getReplacement);
};
