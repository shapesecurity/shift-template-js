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

let { reduce, ConcatReducer, adapt } = require('shift-reducer');

let defaultMatcher = require('./default-matcher.js');


let flatten = adapt((data, node) => [node].concat(data), new ConcatReducer);

module.exports = function findNodes({ tree, locations, comments }, { matcher = defaultMatcher } = {}) {
  let markers = comments
    .map(comment => {
      let { text, start } = comment;
      let match = matcher(text);
      if (match === null) {
        return null;
      }
      return { start: start.offset, name: match.name, predicate: match.predicate, comment };
    })
    .filter(m => m !== null);

  if (markers.length === 0) {
    return [];
  }

  let nodes = reduce(flatten, tree);
  let nodesAndLocations = nodes
    .map(node => {
      if (!locations.has(node)) {
        if (node.type === 'BindingIdentifier' && node.name === '*default*') {
          return null;
        }
        throw new TypeError(`Missing location information for node ${JSON.stringify(node)}`);
      }
      let loc = locations.get(node);
      return { start: loc.start.offset, end: loc.end.offset, node };
    })
    .filter(i => i !== null)
    .sort((a, b) => a.start - b.start);

  let joinedByStart = nodesAndLocations.reduce((acc, { start, end, node }) => {
    if (acc.length === 0 || acc[acc.length - 1].start < start) {
      acc.push({ start, nodes: [{ end, node }] });
    } else {
      // Otherwise starts are equal, because nodes are sorted by start index
      acc[acc.length - 1].nodes.push({ end, node });
    }
    return acc;
  }, []);


  let out = [];

  let nodeWalker = joinedByStart[Symbol.iterator]();

  let currentBlockOfNodes = nodeWalker.next().value; // we know it's not empty; there is at least the program node itself
  for (let marker of markers) {
    while (currentBlockOfNodes.start < marker.start) {
      let ret = nodeWalker.next();
      if (ret.done) {
        throw new TypeError(`Couldn't find node following marker ${marker.name}`);
      }
      currentBlockOfNodes = ret.value;
    }
    // At this point we know currentBlockOfNodes is the set of nodes which start immediately following the marker we're looking at.

    let ofCorrectType = currentBlockOfNodes.nodes.filter(({ node }) => marker.predicate(node));
    if (ofCorrectType.length === 0) {
      throw new TypeError(`Couldn't find any nodes matching predicate for marker ${marker.name}`);
    }
    if (ofCorrectType.length === 1) {
      // common case
      out.push({ name: marker.name, node: ofCorrectType[0].node, comment: marker.comment });
    } else {
      let outermostEnd = -1;
      let outermost = null;
      ofCorrectType.forEach(({ end, node }) => {
        if (end > outermostEnd) {
          outermostEnd = end;
          outermost = node;
        }
      });
      ofCorrectType.forEach(({ end, node }) => {
        if (end === outermostEnd && node !== outermost) {
          throw new TypeError(`Marker ${marker.name} is ambiguous: could be
  ${JSON.stringify(outermost)}
or
  ${JSON.stringify(node)}`);
        }
      });
      out.push({ name: marker.name, node: outermost, comment: marker.comment });
    }
  }
  return out;
};
