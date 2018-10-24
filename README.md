# Shift Template

## About

This module provides a templating system based on [Shift format](https://github.com/shapesecurity/shift-spec) ASTs for JavaScript programs.


## Status

[Stable](http://nodejs.org/api/documentation.html#documentation_stability_index).


## Installation

```sh
npm install shift-template
```


## Usage

This module exports three functions: `findNodes`, `applyTemplate`, and `applyStructuredTemplate`.

`findNodes` takes the output of `parse{Script,Module}WithLocation` from [shift-parser](https://github.com/shapesecurity/shift-parser-js) as run on a source text which has comments in a certain format before nodes of interest. An optional second parameter to `findNodes` allows customizing the comment format; by default it is `/*# name #*/` or `/*# name # type #*/`. It returns a list of objects of the form `{ name, node, comment }`, where the first property is a name given in a marker comment, the second is the node which follows that marker, and the third an object with metadata about the comment.

For example,

```js
let { parseScriptWithLocation } = require('shift-parser');

let src = `
  a + /*# foo # IdentifierExpression #*/ b;
  0 + /*# bar #*/ 1;
`;

let { tree, locations, comments } = parseScriptWithLocation(src);

let names = findNodes({ tree, locations, comments });

console.log(names);
/*
[
  {
    name: "foo",
    node: {
      type: "IdentifierExpression",
      name: "b",
    },
    comment: { text, type, start, end },
  },
  {
    name: "bar",
    node: {
      type: "LiteralNumericExpression",
      value: 1,
    },
    comment: { text, type, start, end },
  },
]
*/
```


`applyTemplate` is a convenience function built on top of `findNodes` which takes source code annotated with marking comments as above and an object giving replacing functions for each marker. It returns an AST corresponding to that of the original source with all marked nodes replaced by the corresponding supplied replacement.

For example,

```js
let Shift = require('shift-ast/checked');

let src = `
a + /*# foo # IdentifierExpression #*/ b;
0 + /*# bar #*/ 1;
`;


let replaced = applyTemplate(src, {
  foo: node => new Shift.IdentifierExpression({ name: node.name + '_' }),
  bar: node => new Shift.LiteralNumericExpression({ value: node.value + 1 }),
});

```
produces an AST corresponding to the script
```js
a + b_;
0 + 2;
```

The replacing functions are passed a node which has already had the template applied to its children, so you can safely replace both an inner node and its parent as long as the function generating a replacement for the parent uses its argument.

A more sophisiticated example (a build-time implementation of an `autobind` class decorator) is in [example.js](example.js).


`applyStructuredTemplate` extends the above by giving special meaning to labels of the form `if foo`, `unless foo`, and `for each foo of bar`. For `if` and `unless`, you should supply a property named `foo` holding a boolean in the second parameter. For `for each`, you should supply a property named `bar` holding a list of objects of the same shape as the full parameter.

`if`-marked nodes are included as long as the condition is `true`; `unless` are included as long as it is `false`. These markers may only be included on nodes that are in an optional or list position in the AST. In the case of a list of optional nodes, omitting the node is treated as omitting the entry from the list, rather than putting in an empty value in the list.

For `for each` nodes, the node will be included multiple times. Each time, the template will be evaluated using the values supplied in the corresponding list. The values may be referenced by  prefixing their name with the variable name and `::`. The `for each` marker may only be included on nodes which are in list position in the AST.

Multiple of these structural labels may be used on a single node.

For example,

```js
let Shift = require('shift-ast/checked');

let script = `
  [
    /*# if markerAtStart #*/
      { prop: 'marker' },
    /*# for each x of xs #*/
      { prop: /*# x::prop #*/ null },
    /*# unless markerAtStart #*/
      { prop: 'marker' },
  ]
`;

let templateValues = {
  markerAtStart: false,
  xs: [
    { prop: () => new Shift.LiteralNumericExpression({ value: 1 }) },
    { prop: () => new Shift.LiteralNumericExpression({ value: 2 }) },
    { prop: () => new Shift.LiteralNumericExpression({ value: 3 }) },
  ]
};

let replaced = applyStructuredTemplate(script, templateValues);

```
produces an AST corresponding to the script
```js
[
  { prop: 1 },
  { prop: 2 },
  { prop: 3 },
  { prop: 'marker' },
]
```

### Handling ambiguous markers

It is possible for two nodes two start at exactly the same place. Often it suffices to resolve the ambiguity by specifying the type of the node of interest. However, it is possible for two nodes of the same type to start at exactly the same place, as in `a + b + c` (which has two BinaryExpression nodes starting at the beginning of the source). In these cases the outermost is picked. If there is no unique outermost node satisfying the type constraint, an error is thrown.


### Specifying comment format

Both functions take an optional final argument which is an options bag. Currently it supports one option, `matcher`, which is a function for parsing comments. This function, if supplied, should take the text of a comment and return either `null` to indicate that the comment is not to be treated as marking a node or an object of type `{ name: string, predicate: Node => bool }` to indicate that it is to be treated as marking a node. The function supplied as `predicate` will be used to test nodes to see if they match the label: for example, the default matcher when given `/*# label # type #*/` returns `{ name: 'label', predicate: node => node.type === "type" }` and when given `/*# label #*/` returns `{ name: 'label', predicate: node => true }`.


### Nodes with multiple names, names with multiple nodes

`findNodes` permits both nodes which have multiple names and names which occur multiple times. Depending on your application, you may wish to forbid one or both of these.

If you just want to get a map from names to nodes, you can do
```js
let names = findNodes(data);
let map = new Map(namePairs.map(({ name, node }) => [name, node]);
if (map.size < namePairs.length) {
  throw new TypeError('duplicate name');
}
```


`applyTemplate` forbids nodes which have multiple names, but allows names which occur multiple times.


### Validating correctness

`applyTemplate` enforces that the tree it produces conforms to the types in the Shift specification. However, some such trees are not valid programs. It is the responsibility of the calling code to ensure it does not produce such a well-typed but invalid program, or to run both the `EarlyErrorChecker` from [shift-parser](https://github.com/shapesecurity/shift-parser-js/) and the Validator from [shift-validator](https://github.com/shapesecurity/shift-validator-js) to check for invalid programs.


## Contributing

* Ensure you've signed the [CLA](https://github.com/shapesecurity/CLA/).
* Open a Github issue with a description of your desired change. If one exists already, leave a message stating that you are working on it with the date you expect it to be complete.
* Fork this repo, and clone the forked repo.
* Install dependencies with `npm install`.
* Build and test in your environment with `npm run build && npm test`.
* Create a feature branch. Make your changes. Add tests.
* Build and test in your environment with `npm run build && npm test`.
* Make a commit that includes the text "fixes #*XX*" where *XX* is the Github issue.
* Open a Pull Request on Github.


## License

    Copyright 2018 Shape Security, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
