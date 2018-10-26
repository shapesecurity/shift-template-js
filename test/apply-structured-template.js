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
const { applyStructuredTemplate } = require('..');


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

function checkApplication(source, templateValues, expectedSource) {
  const expected = parseScriptWithLocation(expectedSource).tree;
  const actual = applyStructuredTemplate(source, templateValues);
  assert.deepStrictEqual(stripPrototypes(actual), stripPrototypes(expected));
}

function fails(source, templateValues) {
  assert.throws(() => applyStructuredTemplate(source, templateValues));
}


describe('applyStructuredTemplate', () => {
  it('basic template', () => {
    const source = 'a + /*# label #*/ b';
    const expected = 'a + null';
    checkSimpleApplication(source, new Shift.LiteralNullExpression, expected);
  });

  it('if/unless', () => {
    const source = ' start; /*# if a #*/ a; /*# if b #*/ b; /*# unless c #*/ c; /*# unless d #*/ d; end; ';
    const expected = 'start; a; d; end;';
    checkApplication(source, { a: true, b: false, c: true, d: false }, expected);
  });

  it('for-each', () => {
    const source = '[start, /*# for each x of xs #*/ /*# x::node #*/ PLACEHOLDER, end]; ';
    const expected = '[start, 1, 2, 3, end]';
    checkApplication(source, { xs: [1, 2, 3].map(v => ({ node: () => new Shift.LiteralNumericExpression({ value: v }) })) }, expected);
  });

  it('maybe supports if', () => {
    const source = '(function /*# if includeName #*/ name(){}); (function /*# unless includeName #*/ name(){});';
    const expected = '(function name(){}); (function(){});';
    checkApplication(source, { includeName: true }, expected);
  });

  it('maybe does not support for-each', () => {
    const source = '(function /*# for each x of xs #*/ name(){});';
    fails(source, { xs: [] });
  });

  it('does not support if on mandatory nodes', () => {
    const source = '(function name /*# if foo #*/ (){});';
    fails(source, { foo: true });
  });

  it('does not support for-each on mandatory nodes', () => {
    const source = '(function name /*# for each foo of foos #*/ (){});';
    fails(source, { foos: [] });
  });

  it('nesting', () => {
    const source = `
      f(
        /*# for each x of xs #*/
          /*# if x::include #*/
            /*# for each y of x::ys #*/
              /*# y::arg #*/ a
      );`;
    const expected = 'f(a_1, a_2, a_5, a_6);';
    const templateValues = {
      xs: [
        {
          include: true,
          ys:
          [
            { arg: node => ({ type: 'IdentifierExpression', name: node.name + '_1' }) },
            { arg: node => ({ type: 'IdentifierExpression', name: node.name + '_2' }) },
          ],
        },
        {
          include: false,
        },
        {
          include: true,
          ys:
          [
            { arg: node => ({ type: 'IdentifierExpression', name: node.name + '_5' }) },
            { arg: node => ({ type: 'IdentifierExpression', name: node.name + '_6' }) },
          ],
        },
      ],
    };
    checkApplication(source, templateValues, expected);
  });

  it('module', () => {
    const source = ' /*# if one #*/ import one from "bar"; /*# unless one #*/ import two from "bar";';
    const expected = parseModuleWithLocation('import two from "bar";').tree;
    const templateValues = { one: false };
    const actual = applyStructuredTemplate(source, templateValues, { isModule: true });
    assert.deepStrictEqual(stripPrototypes(actual), stripPrototypes(expected));
  });
});
