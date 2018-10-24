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

let { parseScriptWithLocation } = require('shift-parser');
let { thunkedReduce } = require('shift-reducer');
let spec = require('shift-spec').default;
let Shift = require('shift-ast/checked');

let defaultMatcher = require('./default-matcher.js');
let findNodes = require('./find-nodes.js');


// TODO dedup these with lazy-checked-clone
// TODO consider splitting these and the utilities from https://github.com/shapesecurity/shift-reducer-js/blob/es2016/scripts/lib/utilities.js into their own project
function isNodeOrUnionOfNodes(type) {
  return type.typeName === 'Union' && type.arguments.every(isNodeOrUnionOfNodes) || spec.hasOwnProperty(type.typeName);
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


/*
  labels are of shape
    { type: 'bare', name: string }
  | { type: 'if', condition: string }
  | { type: 'loop', variable: string, values: string }

  templateValues is of shape
  [ name -> (node -> node) | boolean | [templateValues] ]

  a 'bare' label must correspond to a `node -> node`
  a 'if' label must correspond to a boolean
  a 'loop' (values) label must correspond to [templateValues]
*/
function applyLabels(reducer, childThunk, remainingLabels) { // returns a list of nodes
  if (remainingLabels.length === 0) {
    reducer.currentNodeMayHaveStructuredLabel = true;
    let result = childThunk();
    return [result];
  }
  let [head, ...tail] = remainingLabels;
  if (head.type === 'if') {
    let condition = reducer.templateValues.get(head.condition);
    if (typeof condition !== 'boolean') {
      throw new TypeError(`Condition ${head.condition} not found`);
    }
    if (!condition) {
      return [];
    }
    return applyLabels(reducer, childThunk, tail);
  }
  if (head.type === 'loop') {
    let variable = head.variable;
    let values = reducer.templateValues.get(head.values);
    if (!Array.isArray(values)) { // TODO should just be any iterable, I guess
      throw new TypeError(`Loop values ${head.values} not found`);
    }
    let oldNodes = reducer.templateValues;
    return [].concat.apply([], values.map(iterationMap => {
      if (!(iterationMap instanceof Map)) {
        iterationMap = Object.entries(iterationMap); // TODO this might not work on old node
      }
      let templateValuesAndIterationNodes = new Map(oldNodes);
      for (let [key, value] of iterationMap) {
        let namespaced = variable + '::' + key;
        if (templateValuesAndIterationNodes.has(namespaced)) {
          throw new TypeError(`Name ${namespaced} already exists!`);
        }
        templateValuesAndIterationNodes.set(namespaced, value);
      }
      reducer.templateValues = templateValuesAndIterationNodes;
      let result = applyLabels(reducer, childThunk, tail);
      reducer.templateValues = oldNodes;
      return result;
    }));
  }
  throw new TypeError(`Unrecognized structured label type ${head.type}`);
}


class ReduceStructured {
  constructor(nodeToLabels, templateValues) { // TODO rename `templateValues`
    this.nodeToLabels = nodeToLabels;
    this.templateValues = templateValues;
    this.currentNodeMayHaveStructuredLabel = false;
  }
}

for (let typeName of Object.keys(spec)) {
  let type = spec[typeName];
  ReduceStructured.prototype['reduce' + typeName] = function (node, data) {
    let labels = this.nodeToLabels.has(node) ? this.nodeToLabels.get(node) : []; // TODO consider a multimap
    if (!this.currentNodeMayHaveStructuredLabel && labels.some(l => l.type === 'if')) {
      let label = labels.find(l => l.type === 'if');
      throw new TypeError(`Node of type ${node.type} with condition ${label.string} is not in an omittable position`);
    }
    if (!this.currentNodeMayHaveStructuredLabel && labels.some(l => l.type === 'loop')) {
      let label = labels.find(l => l.type === 'loop');
      throw new TypeError(`Node of type ${node.type} iterating over ${label.values} is not in a loopable position`);
    }
    this.currentNodeMayHaveStructuredLabel = false;

    let transformed = new Shift[typeName](type.fields.reduce((acc, field) => {
      if (field.name === 'type') {
        return acc;
      }
      if (!isStatefulType(field.type)) {
        acc[field.name] = node[field.name];
        return acc;
      }

      if (field.type.typeName === 'List') {
        // Either a list of node or a list of maybe(node)
        acc[field.name] = [].concat.apply([], data[field.name].map((childThunk, childIndex) => {
          if (childThunk === null) {
            return [null];
          }
          let originalChild = node[field.name][childIndex];
          let childLabels = this.nodeToLabels.has(originalChild) ? this.nodeToLabels.get(originalChild) : [];
          let structuredLabels = childLabels.filter(l => l.type !== 'bare');
          return applyLabels(this, childThunk, structuredLabels);
        })); // poor man's flatmap
        return acc;
      }

      if (field.type.typeName === 'Maybe') {
        // A maybe(node)
        let childThunk = data[field.name];
        if (childThunk === null) {
          acc[field.name] = null;
          return acc;
        }
        let originalChild = node[field.name];
        let childLabels = this.nodeToLabels.has(originalChild) ? this.nodeToLabels.get(originalChild) : [];
        let structuredLabels = childLabels.filter(l => l.type !== 'bare');
        if (structuredLabels.some(l => l.type === 'loop')) {
          let label = structuredLabels.find(l => l.type === 'loop');
          throw new TypeError(`Node of type ${node.type} iterating over ${label.values} is not in a loopable position`);
        }
        let result = applyLabels(this, childThunk, structuredLabels);
        if (result.length === 0) {
          acc[field.name] = null;
          return acc;
        }
        if (result.length === 1) {
          acc[field.name] = result[0];
          return acc;
        }
        throw new Error('unreachable');
      }

      // Otherwise just a node
      acc[field.name] = data[field.name]();
      return acc;
    }, {}));


    let bareLabels = labels.filter(l => l.type === 'bare');
    if (bareLabels.length > 1) {
      throw new TypeError(`Node has multiple labels: ${bareLabels[0].name}, ${bareLabels[1].name}`);
    }
    if (bareLabels.length === 0) {
      return transformed;
    }
    let replacer = this.templateValues.get(bareLabels[0].name);
    if (typeof replacer !== 'function') {
      throw new TypeError(`Replacer ${bareLabels[0].name} not found`);
    }
    return replacer(transformed);
  };
}

module.exports = function applyStructuredTemplate(src, templateValues, { matcher = defaultMatcher } = {}) {
  if (!(templateValues instanceof Map)) {
    templateValues = new Map(Object.entries(templateValues)); // TODO this might not work on old node
  }

  let { tree, locations, comments } = parseScriptWithLocation(src);
  let names = findNodes({ tree, locations, comments }, { matcher });

  let nodeToLabels = new Map;
  for (let { name, node } of names) {
    if (!nodeToLabels.has(node)) {
      nodeToLabels.set(node, []);
    }
    let labels = nodeToLabels.get(node);
    // TODO handle `unless`
    if (name.startsWith('if ')) {
      labels.push({ type: 'if', condition: name.substring(3) });
    } else if (name.startsWith('for each')) {
      let split = name.substring('for each'.length).split(' of ');
      if (split.length !== 2) {
        throw new TypeError(`couldn't parse loop label "${name}"`);
      }
      labels.push({ type: 'loop', variable: split[0].trim(), values: split[1].trim() });
    } else {
      labels.push({ type: 'bare', name });
    }
  }

  return thunkedReduce(new ReduceStructured(nodeToLabels, templateValues), tree);
};
