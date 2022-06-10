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

let { parseScriptWithLocation, parseModuleWithLocation, EarlyErrorChecker } = require('shift-parser');
let { thunkedReduce } = require('shift-reducer');
let spec = require('shift-spec');
let Shift = require('shift-ast/checked');

let defaultMatcher = require('./default-matcher.js');
let findNodes = require('./find-nodes.js');
let { isStatefulType } = require('./utilities.js');


let entries = Object.entries || (o => Object.keys(o).map(k => [k, o[k]])); // needed on node 6


/*
  labels are of shape
    { type: 'bare', name: string }
  | { type: 'if', condition: string }
  | { type: 'unless', condition: string }
  | { type: 'loop', variable: string, values: string }

  templateValues is of shape
  [ name -> (node => node) | boolean | [templateValues] ]

  a 'bare' label must correspond to a `node => node`
  a 'if' label must correspond to a boolean
  a 'unless' label must correspond to a boolean
  a 'loop' (values) label must correspond to [templateValues]
*/

class ReduceStructured {
  constructor(nodeToLabels, templateValues) {
    this.nodeToLabels = nodeToLabels;
    this.templateValues = templateValues;
    this.currentNodeMayHaveStructuredLabel = false;
  }

  applyLabels(childThunk, remainingLabels) { // returns a list of nodes
    if (remainingLabels.length === 0) {
      this.currentNodeMayHaveStructuredLabel = true;
      return [childThunk()];
    }
    let [head, ...tail] = remainingLabels;
    if (head.type === 'if' || head.type === 'unless') {
      let condition = this.templateValues.get(head.condition);
      if (typeof condition !== 'boolean') {
        throw new TypeError(`Condition ${JSON.stringify(head.condition)} not found`);
      }
      if (head.type === 'if' && !condition || head.type === 'unless' && condition) {
        return [];
      }
      return this.applyLabels(childThunk, tail);
    }
    if (head.type === 'loop') {
      let variable = head.variable;
      let values = this.templateValues.get(head.values);
      if (!Array.isArray(values)) {
        throw new TypeError(`Loop values ${JSON.stringify(head.values)} not found`);
      }
      let oldValues = this.templateValues;
      return [].concat.apply([], values.map(perIterationTemplateValues => {
        if (!(perIterationTemplateValues instanceof Map)) {
          perIterationTemplateValues = entries(perIterationTemplateValues);
        }
        let merged = new Map(oldValues);
        for (let [key, value] of perIterationTemplateValues) {
          let namespaced = variable + '::' + key;
          if (merged.has(namespaced)) {
            throw new TypeError(`Name ${JSON.stringify(namespaced)} already exists!`);
          }
          merged.set(namespaced, value);
        }
        this.templateValues = merged;
        let result = this.applyLabels(childThunk, tail);
        this.templateValues = oldValues;
        return result;
      }));
    }
    throw new Error('unreachable');
  }
}

for (let [typeName, type] of entries(spec)) {
  ReduceStructured.prototype['reduce' + typeName] = function (node, data) {
    let labels = this.nodeToLabels.has(node) ? this.nodeToLabels.get(node) : [];

    if (!this.currentNodeMayHaveStructuredLabel && labels.some(l => l.type !== 'bare')) {
      let label = labels.find(l => l.type !== 'bare');
      if (label.type === 'if' || label.type === 'unless') {
        throw new TypeError(`Node of type ${node.type} with condition ${JSON.stringify(label.condition)} is not in an omittable position`);
      } else if (label.type === 'loop') {
        throw new TypeError(`Node of type ${node.type} iterating over ${JSON.stringify(label.values)} is not in a loopable position`);
      } else {
        throw new Error('unreachable');
      }
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
          return this.applyLabels(childThunk, structuredLabels);
        }));
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
          throw new TypeError(`Node of type ${node.type} iterating over ${JSON.stringify(label.values)} is not in a loopable position`);
        }
        let result = this.applyLabels(childThunk, structuredLabels);
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
      throw new TypeError(`Node has multiple labels: ${JSON.stringify(bareLabels[0].name)}, ${JSON.stringify(bareLabels[1].name)}`);
    }
    if (bareLabels.length === 0) {
      return transformed;
    }
    let replacer = this.templateValues.get(bareLabels[0].name);
    if (typeof replacer !== 'function') {
      throw new TypeError(`Replacer ${JSON.stringify(bareLabels[0].name)} not found`);
    }
    return replacer(transformed);
  };
}

module.exports = function applyStructuredTemplate(src, templateValues, { matcher = defaultMatcher, isModule = false } = {}) {
  if (!(templateValues instanceof Map)) {
    templateValues = new Map(entries(templateValues));
  }

  let { tree, locations, comments } = (isModule ? parseModuleWithLocation : parseScriptWithLocation)(src, { earlyErrors: false });
  let names = findNodes({ tree, locations, comments }, { matcher });

  let nodeToLabels = new Map;
  for (let { name, node } of names) {
    if (!nodeToLabels.has(node)) {
      nodeToLabels.set(node, []);
    }
    let labels = nodeToLabels.get(node);
    if (name.startsWith('if ')) {
      labels.push({ type: 'if', condition: name.substring('if '.length).trim() });
    } else if (name.startsWith('unless ')) {
      labels.push({ type: 'unless', condition: name.substring('unless '.length).trim() });
    } else if (name.startsWith('for each ')) {
      let split = name.substring('for each '.length).split(' of ');
      if (split.length !== 2) {
        throw new TypeError(`couldn't parse label ${JSON.stringify(name)}`);
      }
      labels.push({ type: 'loop', variable: split[0].trim(), values: split[1].trim() });
    } else {
      labels.push({ type: 'bare', name });
    }
  }

  let result = thunkedReduce(new ReduceStructured(nodeToLabels, templateValues), tree);
  let earlyErrors = EarlyErrorChecker.check(result);
  if (earlyErrors.length > 0) {
    throw new Error(`early error after rendering template: ${earlyErrors[0].message}`);
  }
  return result;
};
