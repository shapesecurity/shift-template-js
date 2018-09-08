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

const { parseScriptWithLocation } = require('shift-parser');
const { findNodes } = require('..');


function fail(message) {
  throw new Error(message);
}

function fails(source) {
  const { tree, locations, comments } = parseScriptWithLocation(source);
  assert.throws(() => findNodes({ tree, locations, comments }));
}

function checkNode(source, getter) {
  checkNodes(source, [{ name: 'label', getter }]);
}

function checkNodes(source, expectedNames) {
  const { tree, locations, comments } = parseScriptWithLocation(source);
  const names = findNodes({ tree, locations, comments });

  if (names.length < expectedNames.length) {
    fail('Too few labels found');
  }
  if (names.length > expectedNames.length) {
    fail('Too many labels found');
  }

  outer: for (const { name: expectedName, getter } of expectedNames) {
    const expectedNode = getter(tree);
    for (const { name, node } of names) {
      if (name === expectedName) {
        assert.strictEqual(node, expectedNode);
        continue outer;
      }
    }
    fail(`Couldn't find label "${expectedName}"`);
  }

  // assert sorted
  let prev = -1;
  for (const { comment } of names) {
    assert(prev < comment.start.offset);
    prev = comment.start.offset;
  }
}

describe('findNodes', () => {
  it('simple', () => {
    const source = 'a + /*# label #*/ b * c; // whee\n';
    checkNode(source, t => t.statements[0].expression.right);
  });

  it('single-line comment', () => {
    const source = `
      //# label #
      class Foo {}
    `;
    checkNode(source, t => t.statements[0]);
  });

  it('label type', () => {
    const source = 'a + /*# label # IdentifierExpression #*/ b * c;';
    checkNode(source, t => t.statements[0].expression.right.left);
  });

  it('label is outermost', () => {
    const sourceT = type => ` /*# label ${type}#*/ a + c + d;`;
    checkNode(sourceT(''), t => t.statements[0]);
    checkNode(sourceT('# BinaryExpression '), t => t.statements[0].expression);
    checkNode(sourceT('# IdentifierExpression '), t => t.statements[0].expression.left.left);
  });

  it('multiple labels', () => {
    const source = `
      a + /*# foo # IdentifierExpression #*/ b;
      0 + /*# bar #*/ 1;
    `;

    checkNodes(source, [
      { name: 'foo', getter: t => t.statements[0].expression.right },
      { name: 'bar', getter: t => t.statements[1].expression.right },
    ]);
  });

  it('multiple labels on one node', () => {
    const source = 'a + /*# foo #*/ /*# bar #*/ b;';

    checkNodes(source, [
      { name: 'foo', getter: t => t.statements[0].expression.right },
      { name: 'bar', getter: t => t.statements[0].expression.right },
    ]);
  });

  it('custom matcher', () => {
    const source = 'a + /*$ label $*/ b;';
    const matcher = string => {
      let match = string.match(/^\$ ([^$]+) \$$/);
      if (match === null) {
        return null;
      }
      return { name: match[1], predicate: () => true };
    };
    const { tree, locations, comments } = parseScriptWithLocation(source);
    const names = findNodes({ tree, locations, comments }, { matcher });

    assert.strictEqual(names.length, 1);
    const { name, node, comment } = names[0];

    assert.strictEqual(name, 'label');
    assert.strictEqual(node, tree.statements[0].expression.right);
    assert.strictEqual(comment, comments[0]);
  });

  it('custom predicate', () => {
    const source = 'a + /*$ b $*/ b + /*$ c $*/ c + /*$ d $*/ (d + e);';
    const matcher = string => {
      let match = string.match(/^\$ ([^$]+) \$$/);
      if (match === null) {
        return null;
      }
      return { name: match[1], predicate: node => node.type === 'IdentifierExpression' && node.name === match[1] };
    };

    const { tree, locations, comments } = parseScriptWithLocation(source);
    const names = findNodes({ tree, locations, comments }, { matcher });

    assert.strictEqual(names.length, 3);
    const [b, c, d] = names;

    assert.strictEqual(b.name, 'b');
    assert.strictEqual(b.node, tree.statements[0].expression.left.left.right);
    assert.strictEqual(b.comment, comments[0]);

    assert.strictEqual(c.name, 'c');
    assert.strictEqual(c.node, tree.statements[0].expression.left.right);
    assert.strictEqual(c.comment, comments[1]);

    assert.strictEqual(d.name, 'd');
    assert.strictEqual(d.node, tree.statements[0].expression.right.left);
    assert.strictEqual(d.comment, comments[2]);
  });
});

describe('findNodes failure cases', () => {
  it('wrong type', () => {
    fails('a + /*# label # IdentifierExpression #*/ 0;');
  });

  it('not a type', () => {
    fails('a + /*# label # NotIdentifierExpression #*/ 0;');
  });

  it('trailing label', () => {
    fails('a /*# label #*/');
  });

  it('ambiguous', () => {
    fails(' /*# label #*/ a'); // can be either the ExpressionStatement or the Expression
  });

  it('missing location info', () => {
    const source = 'a + /*# label #*/ b';
    const { tree } = parseScriptWithLocation(source);
    const { locations, comments } = parseScriptWithLocation(source);
    assert.throws(() => findNodes({ tree, locations, comments }));
  });
});
