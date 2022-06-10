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

const assert = require('assert');

const Shift = require('shift-ast/checked');
const { parseScriptWithLocation, parseModuleWithLocation } = require('shift-parser');
const { applyTemplate } = require('..');


// There's no good way to tell `assert.deepStrictEqual` we don't care about prototypes, so just kill them.
function stripPrototypes(obj, seen = new WeakSet) {
  if (typeof obj !== 'object' || obj === null || seen.has(obj)) {
    return obj;
  }
  seen.add(obj);
  Object.setPrototypeOf(obj, null);
  for (const name of Reflect.ownKeys(obj)) {
    stripPrototypes(obj[name], seen);
  }
  return obj;
}

function checkSimpleApplication(source, replacement, expectedSource) {
  checkApplication(source, { label: () => replacement }, expectedSource);
}

function checkApplication(source, newNodes, expectedSource) {
  const expected = parseScriptWithLocation(expectedSource).tree;
  const actual = applyTemplate(source, newNodes);
  assert.deepStrictEqual(stripPrototypes(actual), stripPrototypes(expected));
}

function fails(source, newNodes) {
  assert.throws(() => applyTemplate(source, newNodes));
}


describe('applyTemplate', () => {
  it('simple', () => {
    const source = 'a + /*# label #*/ b';
    const expected = 'a + null';
    checkSimpleApplication(source, new Shift.LiteralNullExpression, expected);
  });

  it('node based', () => {
    const source = ' /*# increment # LiteralNumericExpression #*/ 42 + /*# increment #*/ 128';
    const expected = '43 + 129';
    checkApplication(source, { increment: node => new Shift.LiteralNumericExpression({ value: node.value + 1 }) }, expected);
  });

  it('module', () => {
    const source = 'import /*# label #*/ foo from "bar";';
    const expected = parseModuleWithLocation('import baz from "bar";').tree;
    const newNodes = { label: () => new Shift.BindingIdentifier({ name: 'baz' }) };
    const actual = applyTemplate(source, newNodes, { isModule: true });
    assert.deepStrictEqual(stripPrototypes(actual), stripPrototypes(expected));
  });
});

describe('applyTemplate failure cases', () => {
  it('multiple names', () => {
    const source = ' /*# one # LiteralNumericExpression #*/ /*# two # LiteralNumericExpression #*/ 42';
    fails(source, {
      one: () => new Shift.LiteralNullExpression,
      two: () => new Shift.LiteralNullExpression,
    });
  });

  it('extra names', () => {
    const source = ' /*# one # LiteralNumericExpression #*/ 1 + /*# two # LiteralNumericExpression #*/ 2';
    fails(source, {
      one: () => new Shift.LiteralNullExpression,
      two: () => new Shift.LiteralNullExpression,
      three: () => new Shift.LiteralNullExpression,
    });
  });

  it('missing names', () => {
    const source = ' /*# one # LiteralNumericExpression #*/ 1 + /*# two # LiteralNumericExpression #*/ 2';
    fails(source, {
      one: () => new Shift.LiteralNullExpression,
    });
  });

  it('suspicious comment', () => {
    const source = 'a + /*# label # */ b';
    fails(source, {});
  });
});
