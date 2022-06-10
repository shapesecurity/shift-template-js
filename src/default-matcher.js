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

let Shift = require('shift-ast/checked');

let validTypes = new Set(Object.keys(Shift));

module.exports = function defaultMatcher(text) {
  let match = text.match(/^# ([^#]+) (?:# ([^#]+) )?#$/);
  if (match === null) {
    if (text.match(/(^\s*#)|(#\s*$)/)) {
      throw new Error('This comment looks kind of like a template comment, but not precisely; this is probably a bug.');
    }
    return null;
  }
  if (typeof match[2] === 'string') {
    let type = match[2];
    if (!validTypes.has(type)) {
      throw new TypeError(`Unrecognized type "${type}"`);
    }
    return { name: match[1], predicate: node => node.type === type };
  }
  return { name: match[1], predicate: () => true };
};
